"""Entry point: CLI, starts pipeline threads + dashboard + tray icon."""

from __future__ import annotations

import argparse
import contextlib
import logging
import multiprocessing
import os
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

import kuzu

from agent import metrics
from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.analyzer.preflight import is_novel
from agent.collectors import collect_all, get_collectors
from agent.collectors.base import RawEvent
from agent.config import Settings, compute_graph_memory_mb, load_config_file, load_settings
from agent.graph import connection as kuzu_conn
from agent.graph.connection import get_connection
from agent.health import start_health_server
from agent.logging_setup import setup_logging
from agent.normalizer import normalize
from agent.platform.tamper_detection import TamperChecker
from agent.processor.entity_extractor import extract_entities
from agent.processor.graph_builder import GraphBuilder
from agent.queue.sqlite_queue import SqliteQueue
from agent.response.actions import ResponsePolicy
from agent.response.baseline import (
    AllowlistRuleCache,
    BaselineGateCache,
    BehaviorBaseline,
    ResponseAllowlist,
    ResponseBlocklist,
)
from agent.response.engine import ResponseAuditLog, ResponseEngine
from agent.schema.kuzu_schema import init_graph_schema
from agent.watchdog import write_heartbeat

# macOS process enrichment (optional)
_enrich_process = None
try:
    if sys.platform == "darwin":
        from agent.collectors.macos_proc_enricher import enrich_process_event

        _enrich_process = enrich_process_event
except ImportError:
    pass

logger = logging.getLogger("agent")

_shutdown = threading.Event()

# Tray icon instance (set in main() if tray is enabled)
_tray_app = None

# Fleet forwarder instance (set in main() if fleet is enabled)
_fleet_forwarder = None

# Flight recorder instance (set in main() — always-on DVR, independent of fleet)
_flight_recorder = None

# Forensic ledger writer instance (Tier 1 capture — set in main())
_ledger_writer = None



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


def _record_to_dvr(entities, ocsf) -> None:
    """Record event to the continuous DVR flight recorder (no filtering)."""
    import time as _time

    event_type = type(ocsf).__name__
    # Only record activity types relevant for forensics
    if event_type not in ("ProcessActivity", "NetworkActivity", "Authentication"):
        return

    proc = entities.processes[0] if entities.processes else None
    proc_name = proc.name if proc else getattr(getattr(ocsf, "process", None), "name", None)
    pid = proc.pid if proc else getattr(getattr(ocsf, "process", None), "pid", None)
    cmd_line = proc.cmd_line if proc else getattr(getattr(ocsf, "process", None), "cmd_line", None)
    username = (entities.users[0].name or entities.users[0].id) if entities.users else None

    # For network events: record one row per IP
    if entities.ips:
        for ip in entities.ips:
            port = None
            for edge in entities.connected_edges:
                if edge.get("ip_id") == ip.id:
                    port = edge.get("dst_port")
                    break
            if port is None:
                ep = getattr(ocsf, "dst_endpoint", None) or getattr(ocsf, "src_endpoint", None)
                if ep:
                    port = ep.port or None
            _flight_recorder.record({
                "timestamp": _time.time(),
                "event_type": event_type,
                "process_name": proc_name,
                "pid": pid,
                "username": username,
                "cmd_line": cmd_line,
                "remote_ip": ip.address,
                "remote_port": port,
            })
    else:
        # Process/auth events without IPs
        _flight_recorder.record({
            "timestamp": _time.time(),
            "event_type": event_type,
            "process_name": proc_name,
            "pid": pid,
            "username": username,
            "cmd_line": cmd_line,
        })


def processor_thread(
    settings: Settings,
    queue: SqliteQueue,
    kuzu_db: kuzu.Database,
    ioc_db=None,
    allowlist_cache: AllowlistRuleCache | None = None,
    baseline_gate: BaselineGateCache | None = None,
    response_engine: ResponseEngine | None = None,
    blocklist: ResponseBlocklist | None = None,
    fast_blocklist=None,
) -> None:
    """Process queued events: normalize, extract entities, write to graph."""
    from agent.graph.write_queue import WriteJob, WriteJobType
    from agent.graph.write_queue import submit as submit_write
    from agent.processor.allowlist_filter import filter_entities, has_entities
    from agent.processor.baseline_gate import gate_baselined_edges
    from agent.processor.self_filter import filter_agent_noise

    _agent_pid = os.getpid()

    _last_prune = time.monotonic()
    _PRUNE_INTERVAL = 300.0  # Run retention pruning every 5 minutes

    # Initialize port mapper for connection context enrichment
    port_mapper = None
    if settings.process_identity_enabled:
        try:
            from agent.enrichment.port_mapper import PortMapper

            port_mapper = PortMapper(refresh_interval=settings.port_mapper_refresh_interval)
            logger.info("Port mapper initialized (refresh every %.0fs)", settings.port_mapper_refresh_interval)
        except Exception:
            logger.debug("Port mapper not available", exc_info=True)

    # Store fast_blocklist in dashboard state for invalidation from API endpoints
    try:
        from agent.dashboard import server as dashboard_server

        dashboard_server._state["fast_blocklist"] = fast_blocklist
    except Exception:
        pass

    logger.info("Started processor thread")

    while not _shutdown.is_set():
        # Check if agent is paused
        if _is_paused():
            _shutdown.wait(timeout=settings.processor_poll_interval)
            continue

        try:
            batch_size = settings.processor_batch_size
            batch = queue.pop_batch(batch_size)
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
                        # Real-time IOC feed matching (instant, no LLM wait)
                        if ioc_db is not None:
                            ioc_db.refresh_if_stale()
                            ioc_matches = _check_ioc_matches(ioc_db, ocsf, event_id)
                            for finding in ioc_matches:
                                queue.store_finding(finding)
                                _push_finding_notification(finding)

                        entities = extract_entities(
                            ocsf,
                            event_id,
                            dga_allowlist=set(settings.dga_allowlist),
                            dga_threshold=settings.dga_score_threshold,
                            port_mapper=port_mapper,
                        )
                        # ── Forensic Ledger (Tier 1, unfiltered) ──
                        if _ledger_writer is not None:
                            _ledger_writer.record(ocsf, entities, event_id)
                        # ── DVR flight recorder (non-blocking) ──
                        if _flight_recorder is not None:
                            _record_to_dvr(entities, ocsf)
                        # Agent self-allowlist: suppress own telemetry
                        self_removed = filter_agent_noise(entities, _agent_pid)
                        if self_removed:
                            metrics.events_self_filtered.inc(self_removed)
                        if not has_entities(entities):
                            event_ids.append(event_id)
                            continue
                        # ── Synchronous fast-path enforcement ──
                        if fast_blocklist and response_engine:
                            hit = fast_blocklist.evaluate(entities, ocsf, event_id)
                            if hit:
                                finding, match_desc = hit
                                queue.store_finding(finding)
                                _push_finding_notification(finding)
                                try:
                                    _trigger_response(response_engine, finding, [(event_id, ocsf)], kuzu_db=kuzu_db)
                                except Exception:
                                    logger.exception("Fast-path response failed for event %d", event_id)
                                metrics.events_fast_blocked.inc()
                                event_ids.append(event_id)
                                continue  # Skip graph insertion and LLM pipeline
                        # Gate file READ edges behind config flag
                        if not settings.file_read_tracking:
                            entities.file_edges = [e for e in entities.file_edges if e["operation"] != "READ"]
                        # Pre-graph allowlist filter
                        if allowlist_cache:
                            al_removed = filter_entities(entities, allowlist_cache.get_rules())
                            if al_removed:
                                metrics.events_allowlist_filtered.inc(al_removed)
                            if not has_entities(entities):
                                event_ids.append(event_id)
                                continue
                        # Baseline graph gating (edge-level, non-learning modes only)
                        if baseline_gate and settings.baseline_graph_gating and settings.response_mode != "learning":
                            gated = gate_baselined_edges(entities, baseline_gate)
                            if gated:
                                metrics.edges_baseline_gated.inc(gated)
                            if not has_entities(entities):
                                event_ids.append(event_id)
                                continue
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
                submit_write(WriteJob(job_type=WriteJobType.ENTITY_BATCH, payload=entity_batch))
            if event_ids:
                queue.mark_processed(event_ids)
                logger.debug("Processed %d events", len(event_ids))

            # Periodic retention pruning
            now = time.monotonic()
            if now - _last_prune >= _PRUNE_INTERVAL:
                _last_prune = now
                try:
                    pruned = queue.prune_old_events(settings.event_retention_hours)
                    if pruned:
                        logger.info("Pruned %d old events (retention=%dh)", pruned, settings.event_retention_hours)
                except Exception:
                    logger.debug("Event pruning failed", exc_info=True)

        except Exception:
            logger.exception("Processor cycle failed")
            _shutdown.wait(timeout=settings.processor_poll_interval)


def analyzer_thread(
    settings: Settings,
    queue: SqliteQueue,
    kuzu_db: kuzu.Database,
    response_engine: ResponseEngine | None = None,
    ioc_db=None,
    ledger_reader=None,
) -> None:
    """Periodically analyze novel events with the LLM."""
    analyzer = LlmAnalyzer(settings, kuzu_db, queue, ioc_db=ioc_db, ledger_reader=ledger_reader)
    conn = get_connection() if settings.kuzu_persistent_enabled else None
    # Start near the current queue head so we don't re-analyze the entire
    # history on every restart.  Only look back ~1000 events.
    last_analyzed_id = max(0, queue.max_processed_id() - 1000)
    logger.info("Started analyzer thread (resuming from event %d)", last_analyzed_id)

    while not _shutdown.is_set():
        _shutdown.wait(timeout=settings.analyzer_interval)
        if _shutdown.is_set():
            break

        # Skip analysis when paused
        if _is_paused():
            continue

        try:
            # Get recently processed events
            recent = queue.get_processed_since(last_analyzed_id, limit=1000)
            if not recent:
                continue

            # Normalize and filter for novel behavior
            novel_events = []
            for event_id, raw_data in recent:
                last_analyzed_id = max(last_analyzed_id, event_id)
                try:
                    raw = RawEvent.from_dict(raw_data)
                    ocsf = normalize(raw)
                    if ocsf is not None and (conn is None or is_novel(conn, ocsf, settings.novel_edge_threshold)):
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

                    # Queue finding for fleet forwarding
                    if _fleet_forwarder is not None:
                        try:
                            _fleet_forwarder.forward_finding(finding)
                        except Exception:
                            logger.debug("Fleet forward failed for finding %s", finding.id, exc_info=True)

                    # Push finding to tray notification queue
                    _push_finding_notification(finding)

                    # Trigger response engine for each finding
                    if response_engine:
                        try:
                            _trigger_response(response_engine, finding, novel_events, kuzu_db=kuzu_db, graph_conn=conn)
                        except Exception:
                            logger.exception("Response engine failed for finding %s", finding.id)

                if findings:
                    logger.info("Stored %d findings from LLM", len(findings))
            else:
                logger.debug("No novel events in batch of %d", len(recent))

        except Exception:
            logger.exception("Analyzer cycle failed")


def forwarder_thread(
    settings: Settings,
    forwarder,
) -> None:
    """Periodically drain the forwarding queue and send heartbeats to the fleet server."""
    logger.info("Started forwarder thread")
    last_heartbeat = 0.0

    while not _shutdown.is_set():
        try:
            if not _is_paused():
                forwarder.drain_queue()

                now = time.monotonic()
                if now - last_heartbeat >= settings.fleet_heartbeat_interval:
                    forwarder.send_heartbeat()
                    last_heartbeat = now
        except Exception:
            logger.exception("Forwarder cycle failed")

        _shutdown.wait(timeout=settings.fleet_forward_interval)


def reaper_thread(settings: Settings, kuzu_db: kuzu.Database) -> None:
    """Graph reaper: TTL-based pruning with memory pressure awareness.

    Monitors RSS vs. memory limit and adjusts pruning aggressiveness.
    Collectors NEVER pause — the forensic ledger captures all telemetry.

    Pressure tiers (RSS / memory limit):
      normal    (<75%): configured TTL, prune every hour
      warning   (75-90%): 2h TTL, more aggressive edge-only prune + CHECKPOINT
      critical  (>90%): 5min TTL, edge-only prune + high-degree pruning + CHECKPOINT

    All write operations are submitted to the MPSC write queue.
    """
    from agent.graph.reaper import (
        DB_SIZE_EMERGENCY_THRESHOLD_MB,
        get_memory_limit_mb,
        get_rss_mb,
        measure_db_dir_size_mb,
    )
    from agent.graph.write_queue import WriteJob, WriteJobType
    from agent.graph.write_queue import submit as submit_write

    WAKE_INTERVAL = 60.0
    FULL_PRUNE_INTERVAL = 3600.0

    memory_limit_mb = get_memory_limit_mb()
    logger.info(
        "Started reaper thread (ttl=%dh, wake=%ds, memory_limit=%.0fMB)",
        settings.graph_ttl_hours,
        int(WAKE_INTERVAL),
        memory_limit_mb,
    )

    graph_path = settings.graph_path
    last_full_prune = 0.0
    last_pressure = "normal"
    first_run = True

    while not _shutdown.is_set():
        if first_run:
            first_run = False
            try:
                logger.info("Graph reaper: first-run edge-only prune starting")
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_EDGES,
                    payload={"ttl_hours": settings.graph_ttl_hours},
                ))
                last_full_prune = time.monotonic()
            except Exception:
                logger.exception("Graph reaper first-run prune failed")
            _shutdown.wait(timeout=WAKE_INTERVAL)
            continue

        _shutdown.wait(timeout=WAKE_INTERVAL)
        if _shutdown.is_set():
            break

        try:
            rss_mb = get_rss_mb()
            db_size_mb = measure_db_dir_size_mb(graph_path)
            metrics.graph_db_size_mb.set(db_size_mb)
            metrics.graph_rss_mb.set(rss_mb)

            # --- Compute pressure tier from RSS ---
            ratio = rss_mb / memory_limit_mb if memory_limit_mb > 0 else 0.0

            if ratio > 0.90:
                pressure = "critical"
                effective_ttl = 5.0 / 60.0  # 5 minutes
                metrics.graph_pressure_level.set(3)
            elif ratio > 0.75:
                pressure = "warning"
                effective_ttl = min(settings.graph_ttl_hours, 2.0)
                metrics.graph_pressure_level.set(2)
            else:
                pressure = "normal"
                effective_ttl = float(settings.graph_ttl_hours)
                metrics.graph_pressure_level.set(0)

            # Log pressure transitions
            if pressure != last_pressure:
                logger.warning(
                    "Memory pressure: %s -> %s (RSS=%.0fMB / %.0fMB = %.0f%%, TTL=%.2fh)",
                    last_pressure, pressure,
                    rss_mb, memory_limit_mb, ratio * 100,
                    effective_ttl,
                )
                last_pressure = pressure

            now = time.monotonic()

            # --- Decide what to prune ---
            if pressure == "critical":
                # Edge-only prune + high-degree node pruning + CHECKPOINT
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_EDGES,
                    payload={"ttl_hours": effective_ttl},
                ))
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_HIGH_DEGREE,
                    payload={"edge_threshold": 100, "keep_pct": 0.80},
                ))
                submit_write(WriteJob(job_type=WriteJobType.CHECKPOINT))
                metrics.graph_reaper_emergency_prunes.inc()
                last_full_prune = now
            elif pressure == "warning":
                # Full prune with reduced TTL + CHECKPOINT
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_FULL,
                    payload={"ttl_hours": effective_ttl},
                ))
                submit_write(WriteJob(job_type=WriteJobType.CHECKPOINT))
                last_full_prune = now
            elif db_size_mb > DB_SIZE_EMERGENCY_THRESHOLD_MB:
                # DB file size emergency (even if RSS is fine)
                logger.warning(
                    "Graph reaper: DB size %.1f MB > %d MB threshold",
                    db_size_mb, DB_SIZE_EMERGENCY_THRESHOLD_MB,
                )
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_EDGES,
                    payload={"ttl_hours": effective_ttl},
                ))
                metrics.graph_reaper_emergency_prunes.inc()
                last_full_prune = now
            elif now - last_full_prune >= FULL_PRUNE_INTERVAL:
                # Scheduled: full prune with configured TTL
                submit_write(WriteJob(
                    job_type=WriteJobType.PRUNE_FULL,
                    payload={"ttl_hours": effective_ttl},
                ))
                last_full_prune = now
            else:
                logger.debug(
                    "Graph reaper idle (RSS=%.0fMB, DB=%.1fMB)",
                    rss_mb, db_size_mb,
                )

        except Exception:
            logger.exception("Graph reaper cycle failed")


def graph_writer_thread(settings: Settings, kuzu_db: kuzu.Database) -> None:
    """Single-writer consumer: drains the MPSC write queue using ONE Kuzu connection.

    This is the ONLY thread that writes to Kuzu. All other threads submit
    WriteJob objects to the queue via write_queue.submit().
    """
    import queue as _queue_mod

    # Create the ONE write connection + GraphBuilder for this thread
    from agent.graph.connection import get_writer_connection
    from agent.graph.reaper import prune_edges_only, prune_high_degree_nodes, prune_old_edges
    from agent.graph.write_queue import WriteJobType, get_queue

    conn = get_writer_connection()
    builder = GraphBuilder(kuzu_db, conn=conn)

    q = get_queue()
    logger.info("Graph writer thread started (single-writer mode)")

    while not _shutdown.is_set():
        try:
            job = q.get(timeout=1.0)
        except _queue_mod.Empty:
            continue

        if job.job_type == WriteJobType.SHUTDOWN:
            logger.info("Graph writer received shutdown signal")
            break

        try:
            if job.job_type == WriteJobType.ENTITY_BATCH:
                builder._write_batch_unlocked(job.payload)
            elif job.job_type == WriteJobType.IP_ENRICHMENT:
                builder.upsert_ip_enrichment(job.payload)
            elif job.job_type == WriteJobType.PRUNE_EDGES:
                job._result = prune_edges_only(conn, job.payload["ttl_hours"])
            elif job.job_type == WriteJobType.PRUNE_FULL:
                job._result = prune_old_edges(conn, job.payload["ttl_hours"])
            elif job.job_type == WriteJobType.PRUNE_HIGH_DEGREE:
                job._result = prune_high_degree_nodes(
                    conn,
                    edge_threshold=job.payload.get("edge_threshold", 100),
                    keep_pct=job.payload.get("keep_pct", 0.80),
                )
            elif job.job_type == WriteJobType.PURGE_BASELINE:
                from agent.graph.cleanup import purge_baselined_edges

                job._result = purge_baselined_edges(conn, job.payload["baseline_gate"])
            elif job.job_type == WriteJobType.PURGE_BY_RULE:
                from agent.graph.cleanup import purge_by_rule

                job._result = purge_by_rule(conn, job.payload["rule_type"], job.payload["pattern"])
            elif job.job_type == WriteJobType.CHECKPOINT:
                try:
                    conn.execute("CHECKPOINT")
                except Exception:
                    logger.debug("Checkpoint failed (non-fatal)", exc_info=True)
        except Exception:
            logger.exception("Graph writer failed for %s job", job.job_type.name)
        finally:
            job._result_event.set()  # Wake any sync waiters

    logger.info("Graph writer thread stopped")


def _trigger_response(
    engine: ResponseEngine,
    finding,
    events: list,
    kuzu_db=None,
    graph_conn: kuzu.Connection | None = None,
) -> None:
    """Trigger the response engine for a finding.

    Extracts the target PID and process name from the finding's evidence events.
    When kuzu_db is provided, reconstructs a deterministic chain from the graph
    instead of relying on finding.chain (which may be LLM-derived and incomplete).
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
    dst_ip = ""
    domain = ""

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
                if isinstance(event, NetworkActivity):
                    if event.dst_endpoint and event.dst_endpoint.ip:
                        dst_ip = event.dst_endpoint.ip
                elif isinstance(event, DnsActivity):
                    if event.query_domain:
                        domain = event.query_domain
                elif isinstance(event, FileActivity):
                    target_path = event.file_path
                elif isinstance(event, RegistryActivity):
                    target_path = event.reg_path
                break

    # Build deterministic chain from graph (Gap 3 fix)
    chain = finding.chain
    if kuzu_db and target_pid and target_pid > 0:
        try:
            from agent.graph.queries import get_process_chain, graph_chain_to_chainsteps

            conn = graph_conn or get_connection()
            graph_chain = get_process_chain(conn, target_pid)
            if graph_chain:
                chain = graph_chain_to_chainsteps(graph_chain)
        except Exception:
            logger.debug("Graph chain lookup failed for PID %s, using finding.chain", target_pid, exc_info=True)

    records = engine.respond(
        severity=finding.severity,
        event_id=finding.evidence_event_ids[0] if finding.evidence_event_ids else None,
        target_pid=target_pid,
        target_path=target_path,
        process_name=process_name,
        dst_ip=dst_ip,
        domain=domain,
        finding_title=finding.title,
        chain=chain,
    )

    for rec in records:
        if rec.result not in ("success", "awaiting_approval", "not_required"):
            logger.warning(
                "Response action %s result: %s — %s",
                rec.action_taken,
                rec.result,
                rec.result_detail,
            )


def _check_ioc_matches(ioc_db, ocsf, event_id: int) -> list:
    """Check an OCSF event against the IOC feed database.

    Returns a list of SecurityFinding objects for any matches (usually 0-1).
    """
    from agent.schema.graph_types import ChainStep, SecurityFinding
    from agent.schema.ocsf_types import (
        Authentication,
        DnsActivity,
        FileActivity,
        NetworkActivity,
    )

    matches = []

    def _make_finding(match, entity_type: str, entity_value: str, process_name: str = "", pid: int = 0):
        import uuid
        from datetime import datetime as _dt

        title_map = {
            "ip": "Known Botnet C2 IP Detected",
            "domain": "Known Malicious Domain Detected",
            "sha256": "Known Malware Hash Detected",
        }
        title = f"{title_map.get(match.ioc_type, 'Known Threat IOC Detected')}: {entity_value}"
        chain = []
        if process_name:
            chain.append(
                ChainStep(
                    entity_type="process",
                    entity_id=process_name,
                    entity_name=process_name,
                    pid=pid if pid > 0 else None,
                )
            )
        chain.append(
            ChainStep(
                entity_type=entity_type,
                entity_id=entity_value,
                entity_name=entity_value,
            )
        )

        iocs: dict = {}
        if match.ioc_type == "ip":
            iocs["ips"] = [entity_value]
        elif match.ioc_type == "domain":
            iocs["domains"] = [entity_value]
        elif match.ioc_type == "sha256":
            iocs["files"] = [entity_value]

        return SecurityFinding(
            id=str(uuid.uuid4()),
            timestamp=_dt.now(),
            severity="critical",
            title=title,
            description=(
                f"IOC feed match ({match.feed_name}): {entity_value} — "
                f"{match.description}. This indicator was found in a threat "
                f"intelligence feed with {match.confidence} confidence."
            ),
            affected_entities=[entity_value],
            evidence_event_ids=[event_id],
            recommendation=(
                "Investigate the associated process immediately. Consider "
                "isolating the endpoint and blocking the indicator."
            ),
            chain=chain,
            affected_pids=[pid] if pid > 0 else [],
            iocs=iocs,
        )

    # Extract observables and check each
    ips_to_check: list[str] = []
    domains_to_check: list[str] = []
    hashes_to_check: list[str] = []
    process_name = ""
    pid = 0

    if isinstance(ocsf, NetworkActivity):
        if ocsf.process:
            process_name = ocsf.process.name
            pid = ocsf.process.pid
        if ocsf.dst_endpoint and ocsf.dst_endpoint.ip:
            ips_to_check.append(ocsf.dst_endpoint.ip)
        if ocsf.src_endpoint and ocsf.src_endpoint.ip:
            ips_to_check.append(ocsf.src_endpoint.ip)

    elif isinstance(ocsf, Authentication):
        if ocsf.src_endpoint and ocsf.src_endpoint.ip:
            ips_to_check.append(ocsf.src_endpoint.ip)

    elif isinstance(ocsf, DnsActivity):
        if ocsf.process:
            process_name = ocsf.process.name
            pid = ocsf.process.pid
        if ocsf.query_domain:
            domains_to_check.append(ocsf.query_domain)
        for ip in ocsf.resolved_ips or []:
            ips_to_check.append(ip)

    elif isinstance(ocsf, FileActivity):
        if ocsf.process:
            process_name = ocsf.process.name
            pid = ocsf.process.pid
        if ocsf.file_hash_sha256:
            hashes_to_check.append(ocsf.file_hash_sha256)

    for ip in ips_to_check:
        match = ioc_db.check_ip(ip)
        if match:
            matches.append(_make_finding(match, "ip", ip, process_name, pid))

    for domain in domains_to_check:
        match = ioc_db.check_domain(domain)
        if match:
            matches.append(_make_finding(match, "domain", domain, process_name, pid))

    for h in hashes_to_check:
        match = ioc_db.check_hash(h)
        if match:
            matches.append(_make_finding(match, "file", h, process_name, pid))

    return matches


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
        append_recent_event(
            {
                "timestamp": raw_data.get("timestamp", ""),
                "source": source,
                "event_type": raw_data.get("event_type", raw_data.get("source", "")),
                "name": fields.get("name", ""),
                "pid": fields.get("pid", ""),
                "message": fields.get("message", ""),
                "fields": fields,
            }
        )
    except Exception:
        pass


def _push_finding_notification(finding) -> None:
    """Push a finding to both the dashboard and tray notification queues."""
    global _tray_app

    # Push to dashboard notification queue
    try:
        from agent.dashboard.server import notification_queue

        notification_queue.appendleft(
            {
                "severity": finding.severity,
                "title": finding.title,
                "id": finding.id,
                "timestamp": time.time(),
            }
        )
    except Exception:
        pass

    # Push to tray icon notification queue
    if _tray_app is not None:
        with contextlib.suppress(Exception):
            _tray_app.push_finding(finding)


def main() -> None:
    global _tray_app

    # Ensure "import agent.main" resolves to THIS module even when launched
    # via "python -m agent.main" (which loads us as __main__).  Without this,
    # deferred imports like `from agent.main import _flight_recorder` in
    # federated_queries.py would get a *second* copy with stale globals.
    sys.modules.setdefault("agent.main", sys.modules[__name__])

    # Set process title so we show as "edr-graph" in Activity Monitor / ps
    try:
        import setproctitle

        setproctitle.setproctitle("edr-graph")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description="edr-graph: Local EDR with Graph-Based Event Correlation")
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.yaml file",
    )
    parser.add_argument("--data-dir", type=str, default=None, help="Data directory path")
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard port (default: 9200)",
    )
    parser.add_argument("--port", type=int, default=None, help="Alias for --dashboard-port")
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
    parser.add_argument(
        "--fleet-url",
        type=str,
        default=None,
        help="Fleet server gRPC address (host:port)",
    )
    parser.add_argument(
        "--fleet-enabled",
        action="store_true",
        default=None,
        help="Enable fleet forwarding to central server",
    )
    parser.add_argument(
        "--agent-id",
        type=str,
        default=None,
        help="Agent UUID for fleet registration",
    )
    parser.add_argument(
        "--registration-key",
        type=str,
        default=None,
        help="Registration key for fleet enrollment",
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
    if args.fleet_url:
        settings.fleet_url = args.fleet_url
    if args.fleet_enabled:
        settings.fleet_enabled = True
    if args.agent_id:
        settings.fleet_agent_id = args.agent_id
    if args.registration_key:
        settings.fleet_registration_key = args.registration_key
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

    # Dynamic memory: auto-detect unless config file explicitly sets graph_max_memory_mb
    overrides = load_config_file(Path(config_path)) if config_path else {}
    if "graph_max_memory_mb" not in overrides:
        settings.graph_max_memory_mb = compute_graph_memory_mb()

    # Ledger reader (shared across dashboard, analyzer, federated queries)
    _ledger_reader = None
    if settings.forensic_ledger_enabled:
        try:
            from agent.ledger.reader import LedgerReader
            _ledger_reader = LedgerReader(settings.data_dir)
        except Exception:
            logger.warning("Failed to create ledger reader", exc_info=True)

    kuzu_db = None
    if settings.kuzu_persistent_enabled:
        # Initialize persistent Kuzu graph
        kuzu_db = kuzu.Database(
            str(settings.graph_path),
            buffer_pool_size=settings.graph_max_memory_mb * 1024 * 1024,
        )
        # Initialize the shared database (thread-local connections created on demand)
        kuzu_conn.init(kuzu_db)
        init_conn = get_connection()
        init_graph_schema(init_conn)
        logger.info("Graph schema initialized (persistent)")

        # Backfill parent_pid for existing processes using psutil
        from agent.processor.graph_builder import backfill_parent_pids

        backfill_parent_pids(kuzu_db)

        # Build in-memory PID index from Kuzu scan
        from agent.graph.pid_index import get_pid_index

        get_pid_index().build(init_conn)
    else:
        logger.info("Persistent Kuzu disabled — using forensic ledger + on-demand graph")
        from agent.graph.pid_index import get_pid_index

        # Build PID index from ledger instead of Kuzu
        if _ledger_reader is not None:
            try:
                get_pid_index().build_from_ledger(_ledger_reader)
            except Exception:
                logger.warning("Failed to build PID index from ledger", exc_info=True)

    # Initialize file attribution cache (for FSEvents PID 0 attribution)
    from agent.enrichment.file_attribution import get_file_attribution_cache

    file_attr = get_file_attribution_cache()
    file_attr.set_agent_pid(os.getpid())

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
    baseline = BehaviorBaseline(settings.db_path)
    baseline_gate = BaselineGateCache(baseline) if settings.baseline_graph_gating else None
    allowlist = ResponseAllowlist(settings.db_path)
    allowlist_cache = AllowlistRuleCache(allowlist)
    blocklist = ResponseBlocklist(settings.db_path)
    response_engine = ResponseEngine(
        policy=policy,
        audit_log=audit_log,
        quarantine_dir=settings.quarantine_dir,
        baseline=baseline,
        allowlist=allowlist,
        blocklist=blocklist,
    )
    response_engine.set_mode(settings.response_mode)

    # Initialize DNS sinkhole
    try:
        from agent.response.dns_sinkhole import DnsSinkhole

        response_engine.dns_sinkhole = DnsSinkhole()
    except Exception:
        logger.debug("DNS sinkhole initialization failed (non-fatal)", exc_info=True)

    logger.info(
        "Response engine initialized (mode=%s, auto_respond=%s, auto_terminate=%s)",
        settings.response_mode,
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

    # Initialize IOC feed database (download in background to avoid blocking startup)
    ioc_db = None
    if settings.ioc_feeds_enabled:
        try:
            from agent.intel.ioc_database import IocDatabase

            ioc_db = IocDatabase(
                refresh_interval_hours=settings.ioc_feeds_refresh_hours,
                exclusion_patterns=settings.ioc_exclusion_patterns,
            )

            def _download_feeds_bg():
                try:
                    ioc_db.download_feeds()
                except Exception:
                    logger.warning("Failed to download IOC feeds", exc_info=True)

            t = threading.Thread(target=_download_feeds_bg, daemon=True, name="ioc-download")
            t.start()
        except Exception:
            logger.warning("Failed to initialize IOC feed database", exc_info=True)

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

        t = threading.Thread(target=heartbeat_loop, daemon=True, name="heartbeat")
        t.start()
        threads.append(t)
        logger.info(
            "Heartbeat thread started (dir=%s, interval=%.0fs)", settings.heartbeat_dir, settings.heartbeat_interval
        )

    # Initialize synchronous fast-path blocklist enforcer (hoisted for forwarder wiring)
    fast_blocklist = None
    if blocklist is not None:
        from agent.processor.synchronous_enforcer import FastBlocklist

        fast_blocklist = FastBlocklist(blocklist)
        logger.info("Fast-path blocklist enforcer initialized")

    # Start single graph writer thread (MUST start before processor/reaper)
    if settings.kuzu_persistent_enabled:
        t = threading.Thread(
            target=graph_writer_thread,
            args=(settings, kuzu_db),
            daemon=True,
            name="graph-writer",
        )
        t.start()
        threads.append(t)

    t = threading.Thread(target=collector_thread, args=(settings, queue), daemon=True, name="collector")
    t.start()
    threads.append(t)

    t = threading.Thread(
        target=processor_thread,
        args=(settings, queue, kuzu_db, ioc_db, allowlist_cache, baseline_gate, response_engine, blocklist, fast_blocklist),
        daemon=True,
        name="processor",
    )
    t.start()
    threads.append(t)

    t = threading.Thread(
        target=analyzer_thread,
        args=(settings, queue, kuzu_db, response_engine, ioc_db, _ledger_reader),
        daemon=True,
        name="analyzer",
    )
    t.start()
    threads.append(t)

    # Initialize forensic ledger (Tier 1 capture — always-on)
    global _fleet_forwarder, _flight_recorder, _ledger_writer
    if settings.forensic_ledger_enabled:
        try:
            from agent.ledger.writer import LedgerWriter

            _ledger_writer = LedgerWriter(settings.data_dir, ttl_hours=settings.forensic_ledger_ttl_hours)
        except Exception:
            logger.warning("Forensic ledger initialization failed", exc_info=True)

    # Initialize flight recorder (continuous DVR — always-on, independent of fleet)
    try:
        from agent.flight_recorder import FlightRecorder

        _flight_recorder = FlightRecorder(settings.data_dir, ttl_hours=settings.flight_recorder_ttl_hours)
    except Exception:
        logger.debug("Flight recorder initialization failed", exc_info=True)

    # Fleet forwarder thread (optional)
    if settings.fleet_enabled and settings.fleet_url:
        try:
            from agent.fleet.forwarder import FleetForwarder

            # Start NTP monitor for clock offset reporting
            ntp_monitor = None
            try:
                from server.ntp_sync import NtpMonitor

                ntp_monitor = NtpMonitor(
                    ntp_server=settings.ntp_server,
                    interval=settings.ntp_sync_interval,
                )
                ntp_monitor.start()
                logger.info("NTP monitor started (server=%s)", settings.ntp_server)
            except Exception:
                logger.debug("NTP monitor not available", exc_info=True)

            _fleet_forwarder = FleetForwarder(settings=settings, queue=queue, ntp_monitor=ntp_monitor)
            _fleet_forwarder.set_enforcement_stages(
                allowlist=allowlist,
                blocklist=blocklist,
                fast_blocklist=fast_blocklist,
                allowlist_cache=allowlist_cache,
            )
            _fleet_forwarder.register()

            # Wire federated query executor so the agent can answer
            # XDR queries from the fleet server against its local Kuzu DB
            try:
                from agent.graph.federated_queries import execute_query as _exec_federated

                _fleet_forwarder.set_query_executor(
                    lambda qt, params: _exec_federated(kuzu_db, qt, params)
                )
            except Exception:
                logger.debug("Federated query executor wiring failed", exc_info=True)

            t = threading.Thread(
                target=forwarder_thread,
                args=(settings, _fleet_forwarder),
                daemon=True,
                name="forwarder",
            )
            t.start()
            threads.append(t)
            logger.info("Fleet forwarder started (url=%s)", settings.fleet_url)
        except Exception:
            logger.warning("Fleet forwarder initialization failed", exc_info=True)

    # Graph reaper thread (TTL pruning) — only when persistent Kuzu is enabled
    if settings.kuzu_persistent_enabled:
        t = threading.Thread(
            target=reaper_thread,
            args=(settings, kuzu_db),
            daemon=True,
            name="reaper",
        )
        t.start()
        threads.append(t)

    # Warm graph for dashboard (when persistent Kuzu is disabled)
    _warm_graph = None
    if not settings.kuzu_persistent_enabled and settings.forensic_ledger_enabled:
        try:
            from agent.ledger.reader import LedgerReader
            from agent.ledger.warm_cache import WarmGraph

            if _ledger_reader is None:
                _ledger_reader = LedgerReader(settings.data_dir)
            _warm_graph = WarmGraph(
                _ledger_reader,
                window_hours=2.0,
                first_window_hours=0.25,
            )
            _warm_graph.start()
            logger.info("Warm graph started (first=15min, full=2h, rebuild=300s)")
        except Exception:
            logger.warning("Warm graph initialization failed", exc_info=True)

    logger.info("All pipeline threads started")

    # Start FastAPI dashboard server (daemon thread)
    if not args.no_dashboard:
        try:
            from agent.dashboard.server import (
                _state as _ds,
            )
            from agent.dashboard.server import (
                init_dashboard,
                start_dashboard_server,
            )

            # Collector thread may have already populated _state["collector_names"]
            # before init_dashboard runs, so read the current value to avoid clobbering.

            collector_names = _ds.get("collector_names", [])

            init_dashboard(
                queue=queue,
                kuzu_db=kuzu_db,
                settings=settings,
                collector_names=collector_names,
                ioc_db=ioc_db,
                response_engine=response_engine,
                baseline=baseline,
                allowlist=allowlist,
                blocklist=blocklist,
                allowlist_cache=allowlist_cache,
                baseline_gate=baseline_gate,
            )
            # Set warm graph and ledger reader for dashboard
            if _warm_graph is not None:
                _ds["warm_graph"] = _warm_graph
            if _ledger_reader is not None:
                _ds["ledger_reader"] = _ledger_reader
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
    use_tray = sys.platform == "darwin" and settings.tray_enabled and not args.no_tray

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

    # Shutdown sequence — signal the graph writer to drain and stop
    if settings.kuzu_persistent_enabled:
        from agent.graph.write_queue import WriteJob, WriteJobType
        from agent.graph.write_queue import submit as _submit_shutdown

        _submit_shutdown(WriteJob(job_type=WriteJobType.SHUTDOWN))
    _shutdown.set()
    if _warm_graph is not None:
        _warm_graph.stop()
    if tamper_checker:
        tamper_checker.stop()
    if _ledger_writer:
        _ledger_writer.stop()
    if _flight_recorder:
        _flight_recorder.stop()
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
