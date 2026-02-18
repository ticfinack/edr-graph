"""Entry point: CLI, starts pipeline threads + dashboard + tray icon."""

from __future__ import annotations

import argparse
import logging
import multiprocessing
import os
from pathlib import Path
import signal
import sys
import threading
import time
import webbrowser

import kuzu

from agent.logging_setup import setup_logging

# macOS process enrichment (optional)
_enrich_process = None
try:
    if sys.platform == "darwin":
        from agent.collectors.macos_proc_enricher import enrich_process_event
        _enrich_process = enrich_process_event
except ImportError:
    pass
from agent.health import start_health_server
from agent import metrics
from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.analyzer.preflight import is_novel
from agent.collectors import collect_all, get_collectors
from agent.collectors.base import RawEvent
from agent.config import Settings, load_settings
from agent.normalizer import normalize
from agent.processor.entity_extractor import extract_entities
from agent.processor.graph_builder import GraphBuilder
from agent.queue.sqlite_queue import SqliteQueue
from agent.platform.tamper_detection import TamperChecker
from agent.response.actions import ResponsePolicy
from agent.response.engine import ResponseAuditLog, ResponseEngine
from agent.schema.kuzu_schema import init_graph_schema
from agent.watchdog import write_heartbeat

logger = logging.getLogger("agent")

_shutdown = threading.Event()

# Tray icon instance (set in main() if tray is enabled)
_tray_app = None


def collector_thread(
    settings: Settings,
    queue: SqliteQueue,
) -> None:
    """Continuously collect raw events and push to SQLite queue."""
    collectors = get_collectors(db_path=str(settings.db_path))
    for c in collectors:
        c.start()
    collector_names = [type(c).__name__ for c in collectors]
    logger.info("Started collector thread with %d collectors", len(collectors))

    # Update dashboard state with collector names
    try:
        from agent.dashboard import server as dashboard_server
        dashboard_server._state["collector_names"] = collector_names
    except Exception:
        pass

    try:
        while not _shutdown.is_set():
            try:
                events = collect_all(collectors)
                if events:
                    json_events = [e.to_json() for e in events]
                    queue.push_many(json_events)
                    logger.debug("Collected %d events", len(events))
            except Exception:
                logger.exception("Collector cycle failed")

            _shutdown.wait(timeout=settings.collector_poll_interval)
    finally:
        for c in collectors:
            c.stop()


def processor_thread(
    settings: Settings,
    queue: SqliteQueue,
    kuzu_db: kuzu.Database,
) -> None:
    """Process queued events: normalize, extract entities, write to graph."""
    builder = GraphBuilder(kuzu_db)

    # Initialize port mapper for connection context enrichment
    port_mapper = None
    if settings.process_identity_enabled:
        try:
            from agent.enrichment.port_mapper import PortMapper
            port_mapper = PortMapper(refresh_interval=settings.port_mapper_refresh_interval)
            logger.info("Port mapper initialized (refresh every %.0fs)", settings.port_mapper_refresh_interval)
        except Exception:
            logger.debug("Port mapper not available", exc_info=True)

    logger.info("Started processor thread")

    while not _shutdown.is_set():
        # Check if agent is paused
        if _is_paused():
            _shutdown.wait(timeout=settings.processor_poll_interval)
            continue

        try:
            batch = queue.pop_batch(settings.processor_batch_size)
            if not batch:
                _shutdown.wait(timeout=settings.processor_poll_interval)
                continue

            event_ids = []
            entity_batch = []
            for event_id, raw_data in batch:
                t0 = time.monotonic()
                try:
                    # Enrich process command lines on macOS
                    if _enrich_process is not None:
                        raw_data = _enrich_process(raw_data)
                    raw = RawEvent.from_dict(raw_data)
                    ocsf = normalize(raw)
                    if ocsf is not None:
                        entities = extract_entities(
                            ocsf,
                            event_id,
                            dga_allowlist=set(settings.dga_allowlist),
                            dga_threshold=settings.dga_score_threshold,
                            port_mapper=port_mapper,
                        )
                        # Gate file READ edges behind config flag
                        if not settings.file_read_tracking:
                            entities.file_edges = [
                                e for e in entities.file_edges
                                if e["operation"] != "READ"
                            ]
                        entity_batch.append(entities)
                        metrics.events_processed_total.labels(
                            source=raw.source,
                            event_type=type(ocsf).__name__,
                        ).inc()

                        # Push to dashboard recent events buffer
                        _push_recent_event(raw_data, raw.source)
                    else:
                        metrics.events_dropped_total.labels(
                            source=raw.source,
                            reason="normalization_returned_none",
                        ).inc()
                    event_ids.append(event_id)
                    metrics.event_processing_latency.observe(time.monotonic() - t0)
                except Exception:
                    logger.debug("Failed to process event %d", event_id, exc_info=True)
                    event_ids.append(event_id)  # Mark as processed to avoid infinite loop
                    metrics.events_dropped_total.labels(
                        source=raw_data.get("source", "unknown"),
                        reason="processing_exception",
                    ).inc()

            if entity_batch:
                builder.write_batch(entity_batch)
            if event_ids:
                queue.mark_processed(event_ids)
                logger.debug("Processed %d events", len(event_ids))

        except Exception:
            logger.exception("Processor cycle failed")
            _shutdown.wait(timeout=settings.processor_poll_interval)


def analyzer_thread(
    settings: Settings,
    queue: SqliteQueue,
    kuzu_db: kuzu.Database,
    response_engine: ResponseEngine | None = None,
) -> None:
    """Periodically analyze novel events with the LLM."""
    analyzer = LlmAnalyzer(settings, kuzu_db, queue)
    conn = kuzu.Connection(kuzu_db)
    last_analyzed_id = 0
    logger.info("Started analyzer thread")

    while not _shutdown.is_set():
        _shutdown.wait(timeout=settings.analyzer_interval)
        if _shutdown.is_set():
            break

        # Skip analysis when paused
        if _is_paused():
            continue

        try:
            # Get recently processed events
            recent = queue.get_processed_since(last_analyzed_id, limit=100)
            if not recent:
                continue

            # Normalize and filter for novel behavior
            novel_events = []
            for event_id, raw_data in recent:
                last_analyzed_id = max(last_analyzed_id, event_id)
                try:
                    raw = RawEvent.from_dict(raw_data)
                    ocsf = normalize(raw)
                    if ocsf is not None and is_novel(conn, ocsf, settings.novel_edge_threshold):
                        novel_events.append((event_id, ocsf))
                except Exception:
                    logger.debug("Failed to pre-flight event %d", event_id, exc_info=True)

            if novel_events:
                logger.info(
                    "Sending %d novel events (of %d) to LLM",
                    len(novel_events),
                    len(recent),
                )
                findings = analyzer.analyze_batch(novel_events)
                for finding in findings:
                    queue.store_finding(finding)

                    # Push finding to tray notification queue
                    _push_finding_notification(finding)

                    # Trigger response engine for each finding
                    if response_engine:
                        try:
                            _trigger_response(response_engine, finding, novel_events)
                        except Exception:
                            logger.exception(
                                "Response engine failed for finding %s", finding.id
                            )

                if findings:
                    logger.info("Stored %d findings from LLM", len(findings))
            else:
                logger.debug("No novel events in batch of %d", len(recent))

        except Exception:
            logger.exception("Analyzer cycle failed")


def _trigger_response(
    engine: ResponseEngine,
    finding,
    events: list,
) -> None:
    """Trigger the response engine for a finding.

    Extracts the target PID and process name from the finding's evidence events.
    """
    from agent.schema.ocsf_types import (
        DnsActivity,
        FileActivity,
        NetworkActivity,
        ProcessActivity,
        RegistryActivity,
    )

    target_pid = None
    process_name = None
    target_path = None

    # Find PID and process name from the evidence events
    evidence_ids = set(finding.evidence_event_ids)
    for event_id, event in events:
        if event_id in evidence_ids or not evidence_ids:
            if isinstance(event, ProcessActivity):
                target_pid = event.process.pid
                process_name = event.process.name
                break
            elif isinstance(event, (NetworkActivity, DnsActivity, FileActivity, RegistryActivity)):
                if event.process:
                    target_pid = event.process.pid
                    process_name = event.process.name
                if isinstance(event, (FileActivity,)):
                    target_path = event.file_path
                elif isinstance(event, (RegistryActivity,)):
                    target_path = event.reg_path
                break

    records = engine.respond(
        severity=finding.severity,
        event_id=finding.evidence_event_ids[0] if finding.evidence_event_ids else None,
        target_pid=target_pid,
        target_path=target_path,
        process_name=process_name,
    )

    for rec in records:
        if rec.result not in ("success", "awaiting_approval", "not_required"):
            logger.warning(
                "Response action %s result: %s — %s",
                rec.action_taken,
                rec.result,
                rec.result_detail,
            )


def _is_paused() -> bool:
    """Check if the agent is paused (via tray icon or dashboard API)."""
    try:
        from agent.dashboard import server as dashboard_server
        return dashboard_server._state.get("paused", False)
    except Exception:
        return False


def _push_recent_event(raw_data: dict, source: str) -> None:
    """Push a processed event to the dashboard's recent events buffer."""
    try:
        from agent.dashboard.server import append_recent_event
        fields = raw_data.get("fields", {})
        append_recent_event({
            "timestamp": raw_data.get("timestamp", ""),
            "source": source,
            "event_type": raw_data.get("event_type", raw_data.get("source", "")),
            "name": fields.get("name", ""),
            "pid": fields.get("pid", ""),
            "message": fields.get("message", ""),
            "fields": fields,
        })
    except Exception:
        pass


def _push_finding_notification(finding) -> None:
    """Push a finding to both the dashboard and tray notification queues."""
    global _tray_app

    # Push to dashboard notification queue
    try:
        from agent.dashboard.server import notification_queue
        notification_queue.appendleft({
            "severity": finding.severity,
            "title": finding.title,
            "id": finding.id,
            "timestamp": time.time(),
        })
    except Exception:
        pass

    # Push to tray icon notification queue
    if _tray_app is not None:
        try:
            _tray_app.push_finding(finding)
        except Exception:
            pass


def main() -> None:
    global _tray_app

    # Set process title so we show as "edr-graph" in Activity Monitor / ps
    try:
        import setproctitle
        setproctitle.setproctitle("edr-graph")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        description="edr-graph: Local EDR with Graph-Based Event Correlation"
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to config.yaml file",
    )
    parser.add_argument(
        "--data-dir", type=str, default=None, help="Data directory path"
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=None,
        help="Dashboard port (default: 9200)",
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Alias for --dashboard-port"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )
    parser.add_argument(
        "--log-format",
        type=str,
        default="text",
        choices=["text", "json"],
        help="Log format: text (console) or json (structured)",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=None,
        help="Health/metrics HTTP port (default: 9100)",
    )
    parser.add_argument(
        "--auto-respond",
        action="store_true",
        default=None,
        help="Auto-execute response actions for CRITICAL severity",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Run without the web dashboard",
    )
    parser.add_argument(
        "--no-tray",
        action="store_true",
        help="Disable the menu bar tray icon (run headless)",
    )
    parser.add_argument(
        "--no-watchdog",
        action="store_true",
        help="Disable watchdog heartbeat",
    )
    parser.add_argument(
        "--no-tamper-check",
        action="store_true",
        help="Disable tamper detection",
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Print default config.yaml to stdout and exit",
    )
    args = parser.parse_args()

    # Generate config and exit
    if args.generate_config:
        from agent.config import generate_default_config
        print(generate_default_config())
        return

    # Configure structured logging
    setup_logging(log_level=args.log_level, log_format=args.log_format)

    # Build settings: config file → env vars → defaults, then CLI overrides
    config_path = Path(args.config) if args.config else None
    settings = load_settings(config_path=config_path)

    # CLI overrides (highest priority)
    if args.data_dir:
        settings.data_dir = Path(args.data_dir)
    if args.dashboard_port:
        settings.dashboard_port = args.dashboard_port
    elif args.port:
        settings.dashboard_port = args.port
    if args.metrics_port:
        settings.metrics_port = args.metrics_port
    if args.auto_respond:
        settings.auto_respond = True
    if args.no_watchdog:
        settings.watchdog_enabled = False
    if args.no_tamper_check:
        settings.tamper_check_enabled = False
    if args.no_tray:
        settings.tray_enabled = False
    settings.ensure_dirs()

    logger.info("Starting edr-graph, data dir: %s", settings.data_dir)

    # Warm process identity cache on macOS
    if sys.platform == "darwin" and settings.process_identity_enabled:
        try:
            from agent.enrichment.process_identity import warm_cache
            warm_cache()
        except Exception:
            logger.debug("Process identity cache warming failed", exc_info=True)

    # Load custom allowlist entries from config
    if settings.allowlist_enabled and settings.allowlist_custom_entries:
        try:
            from agent.enrichment.application_allowlist import load_custom_entries
            load_custom_entries(settings.allowlist_custom_entries)
        except Exception:
            logger.debug("Custom allowlist loading failed", exc_info=True)

    # Initialize SQLite queue
    queue = SqliteQueue(settings.db_path)

    # Start health/metrics server
    start_health_server(
        port=settings.metrics_port,
        queue_depth_fn=queue.count_unprocessed,
    )

    # Initialize Kuzu graph
    kuzu_db = kuzu.Database(str(settings.graph_path))
    init_conn = kuzu.Connection(kuzu_db)
    init_graph_schema(init_conn)
    logger.info("Graph schema initialized")

    # Backfill parent_pid for existing processes using psutil
    from agent.processor.graph_builder import backfill_parent_pids
    backfill_parent_pids(kuzu_db)

    # Initialize response engine
    import sqlite3

    response_conn = sqlite3.connect(str(settings.db_path))
    response_conn.row_factory = sqlite3.Row
    response_conn.execute("PRAGMA journal_mode=WAL")
    response_conn.execute("PRAGMA busy_timeout=5000")
    from agent.schema.queue_schema import init_queue_db

    init_queue_db(response_conn)

    policy = ResponsePolicy(
        auto_respond=settings.auto_respond,
        auto_terminate=settings.auto_terminate,
    )
    audit_log = ResponseAuditLog(response_conn)
    response_engine = ResponseEngine(
        policy=policy,
        audit_log=audit_log,
        quarantine_dir=settings.quarantine_dir,
    )
    logger.info(
        "Response engine initialized (auto_respond=%s, auto_terminate=%s)",
        settings.auto_respond,
        settings.auto_terminate,
    )

    # Start self-protection: tamper detection
    tamper_checker = None
    if settings.tamper_check_enabled:
        agent_dir = Path(__file__).resolve().parent
        tamper_checker = TamperChecker(
            agent_dir=agent_dir,
            check_interval=settings.tamper_check_interval,
        )
        tamper_checker.start()
        logger.info("Tamper detection started (%d files baselined)", len(tamper_checker.baseline))

    # Handle shutdown signals
    def on_signal(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        _shutdown.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Start pipeline threads
    threads = []

    # Heartbeat thread
    if settings.watchdog_enabled:
        def heartbeat_loop():
            while not _shutdown.is_set():
                try:
                    write_heartbeat(settings.heartbeat_dir)
                except Exception:
                    logger.debug("Heartbeat write failed", exc_info=True)
                _shutdown.wait(timeout=settings.heartbeat_interval)

        t = threading.Thread(
            target=heartbeat_loop, daemon=True, name="heartbeat"
        )
        t.start()
        threads.append(t)
        logger.info("Heartbeat thread started (dir=%s, interval=%.0fs)",
                    settings.heartbeat_dir, settings.heartbeat_interval)

    t = threading.Thread(
        target=collector_thread, args=(settings, queue), daemon=True, name="collector"
    )
    t.start()
    threads.append(t)

    t = threading.Thread(
        target=processor_thread,
        args=(settings, queue, kuzu_db),
        daemon=True,
        name="processor",
    )
    t.start()
    threads.append(t)

    t = threading.Thread(
        target=analyzer_thread,
        args=(settings, queue, kuzu_db, response_engine),
        daemon=True,
        name="analyzer",
    )
    t.start()
    threads.append(t)

    logger.info("All pipeline threads started")

    # Start FastAPI dashboard server (daemon thread)
    if not args.no_dashboard:
        try:
            from agent.dashboard.server import (
                init_dashboard,
                start_dashboard_server,
            )

            collector_names = []
            try:
                collectors = get_collectors()
                collector_names = [type(c).__name__ for c in collectors]
            except Exception:
                pass

            init_dashboard(
                queue=queue,
                kuzu_db=kuzu_db,
                settings=settings,
                collector_names=collector_names,
            )
            start_dashboard_server(port=settings.dashboard_port)
            logger.info("Dashboard server started on http://127.0.0.1:%d", settings.dashboard_port)

            # Auto-open browser after a short delay
            if settings.dashboard_auto_open:
                def _open_browser():
                    time.sleep(2)
                    webbrowser.open(f"http://127.0.0.1:{settings.dashboard_port}")

                threading.Thread(target=_open_browser, daemon=True, name="browser-open").start()

        except Exception:
            logger.warning("Failed to start dashboard server", exc_info=True)

    # Main thread: tray icon (macOS) or signal wait
    use_tray = (
        sys.platform == "darwin"
        and settings.tray_enabled
        and not args.no_tray
    )

    if use_tray:
        try:
            from agent.tray.macos_tray import EDRTrayApp

            def _on_pause(paused: bool):
                from agent.dashboard import server as dashboard_server
                dashboard_server._state["paused"] = paused

            def _on_shutdown():
                _shutdown.set()

            _tray_app = EDRTrayApp(
                dashboard_port=settings.dashboard_port,
                notification_cooldown=settings.tray_notification_cooldown,
                notify_on_high=settings.tray_notify_on_high,
                notify_on_critical=settings.tray_notify_on_critical,
                shutdown_callback=_on_shutdown,
                pause_callback=_on_pause,
                status_callback=_get_tray_status(settings, queue),
            )
            logger.info("Starting macOS tray icon (main thread)")
            _tray_app.run()  # Blocks until quit

        except ImportError:
            logger.warning("rumps not available, running without tray icon")
            _wait_for_shutdown()
        except Exception:
            logger.warning("Tray icon failed to start, running headless", exc_info=True)
            _wait_for_shutdown()
    else:
        _wait_for_shutdown()

    # Shutdown sequence
    _shutdown.set()
    if tamper_checker:
        tamper_checker.stop()
    logger.info("Waiting for threads to stop...")
    for t in threads:
        t.join(timeout=5.0)
    queue.close()
    logger.info("edr-graph stopped")


def _get_tray_status(settings: Settings, queue: SqliteQueue):
    """Return a closure that gathers status for the tray icon."""
    start_time = time.time()

    def _status() -> dict:
        uptime = time.time() - start_time
        events_processed = 0
        for metric in metrics.events_processed_total.collect():
            for sample in metric.samples:
                if sample.name == "edr_events_processed_total":
                    events_processed += int(sample.value)

        collector_names = []
        try:
            from agent.dashboard import server as dashboard_server
            collector_names = dashboard_server._state.get("collector_names", [])
        except Exception:
            pass

        # Gather findings summary
        findings_total = 0
        findings_high = 0
        findings_critical = 0
        last_finding_title = None
        try:
            all_findings = queue.get_findings(limit=200)
            findings_total = len(all_findings)
            for f in all_findings:
                sev = f.severity.lower() if f.severity else ""
                if sev == "high":
                    findings_high += 1
                elif sev == "critical":
                    findings_critical += 1
            if all_findings:
                last_finding_title = all_findings[0].title
        except Exception:
            pass

        return {
            "agent_status": "paused" if _is_paused() else "running",
            "uptime_seconds": uptime,
            "events_processed": events_processed,
            "events_per_second": round(events_processed / max(uptime, 1), 1),
            "collector_sources": collector_names,
            "queue_depth": queue.count_unprocessed(),
            "findings_total": findings_total,
            "findings_high": findings_high,
            "findings_critical": findings_critical,
            "last_finding_title": last_finding_title,
        }

    return _status


def _wait_for_shutdown() -> None:
    """Block until shutdown signal received."""
    logger.info("Running headless (Ctrl+C to stop)")
    try:
        while not _shutdown.is_set():
            _shutdown.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
