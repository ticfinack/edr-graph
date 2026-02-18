"""Entry point: CLI, starts pipeline threads + dashboard."""

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


def collector_thread(
    settings: Settings,
    queue: SqliteQueue,
) -> None:
    """Continuously collect raw events and push to SQLite queue."""
    collectors = get_collectors()
    for c in collectors:
        c.start()
    logger.info("Started collector thread with %d collectors", len(collectors))

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
    logger.info("Started processor thread")

    while not _shutdown.is_set():
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
    analyzer = LlmAnalyzer(settings, kuzu_db)
    conn = kuzu.Connection(kuzu_db)
    last_analyzed_id = 0
    logger.info("Started analyzer thread")

    while not _shutdown.is_set():
        _shutdown.wait(timeout=settings.analyzer_interval)
        if _shutdown.is_set():
            break

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


def main() -> None:
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
        "--port", type=int, default=None, help="Dashboard port (default: 8080)"
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
    if args.port:
        settings.dashboard_port = args.port
    if args.metrics_port:
        settings.metrics_port = args.metrics_port
    if args.auto_respond:
        settings.auto_respond = True
    if args.no_watchdog:
        settings.watchdog_enabled = False
    if args.no_tamper_check:
        settings.tamper_check_enabled = False
    settings.ensure_dirs()

    # NiceGUI re-spawns the process — use an env var to detect the original
    is_main = os.environ.get("_EDR_NICEGUI_CHILD") != "1"

    if is_main:
        logger.info("Starting edr-graph, data dir: %s", settings.data_dir)

    # Initialize SQLite queue
    queue = SqliteQueue(settings.db_path)

    # Start health/metrics server
    if is_main:
        start_health_server(
            port=settings.metrics_port,
            queue_depth_fn=queue.count_unprocessed,
        )

    if is_main:
        # Initialize Kuzu graph
        kuzu_db = kuzu.Database(str(settings.graph_path))
        init_conn = kuzu.Connection(kuzu_db)
        init_graph_schema(init_conn)
        logger.info("Graph schema initialized")

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

        # Heartbeat thread — writes agent heartbeat for watchdog monitoring
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

    # Run dashboard on main thread (blocking), or wait for shutdown
    if args.no_dashboard:
        logger.info("Running without dashboard (Ctrl+C to stop)")
        try:
            while not _shutdown.is_set():
                _shutdown.wait(timeout=1.0)
        except KeyboardInterrupt:
            pass
    else:
        from agent.dashboard.app import run_dashboard

        # Mark env so NiceGUI's spawned child skips pipeline startup
        os.environ["_EDR_NICEGUI_CHILD"] = "1"
        logger.info("Starting dashboard on port %d", settings.dashboard_port)
        run_dashboard(
            queue,
            port=settings.dashboard_port,
            refresh_interval=settings.dashboard_refresh_interval,
        )

    # Shutdown (only main process manages threads)
    if is_main:
        _shutdown.set()
        if tamper_checker:
            tamper_checker.stop()
        logger.info("Waiting for threads to stop...")
        for t in threads:
            t.join(timeout=5.0)
    queue.close()
    if is_main:
        logger.info("edr-graph stopped")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
