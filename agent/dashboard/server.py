"""FastAPI dashboard backend.

Serves the web dashboard UI and REST API endpoints for status, findings,
graph queries, events, and audit trail. Runs inside the agent process as
a uvicorn thread to avoid Kuzu concurrent reader issues.

Binds to 127.0.0.1 only (localhost). No authentication for v1.
# TODO: Add authentication if dashboard is exposed beyond localhost.
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import threading
import time
from pathlib import Path
from typing import Any

import kuzu
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from prometheus_client import REGISTRY

from agent import metrics
from agent.graph import queries as gq
from agent.queue.sqlite_queue import SqliteQueue

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

# Shared state — set by the agent on startup
_state: dict[str, Any] = {
    "queue": None,
    "kuzu_db": None,
    "settings": None,
    "start_time": time.time(),
    "paused": False,
    "collector_names": [],
}

# Recent events circular buffer (processor thread appends, API reads)
recent_events: collections.deque = collections.deque(maxlen=1000)
recent_events_lock = threading.Lock()

# Notification queue for tray icon (findings pushed here)
notification_queue: collections.deque = collections.deque(maxlen=100)

app = FastAPI(title="EDR Graph Dashboard", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:*", "http://localhost:*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_queue() -> SqliteQueue:
    q = _state.get("queue")
    if q is None:
        raise HTTPException(503, "Queue not initialized")
    return q


def _get_conn() -> kuzu.Connection:
    db = _state.get("kuzu_db")
    if db is None:
        raise HTTPException(503, "Graph database not initialized")
    return kuzu.Connection(db)


def _get_settings():
    return _state.get("settings")


# ── API Endpoints ─────────────────────────────────────────────────────────


@app.get("/")
async def index():
    """Serve the dashboard SPA."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>EDR Graph Dashboard</h1><p>Static files not found.</p>")


@app.get("/api/status")
async def get_status():
    """Agent status overview."""
    uptime = time.time() - _state["start_time"]
    queue = _get_queue()

    # Gather event counts from Prometheus metrics
    events_processed = 0
    events_dropped = 0
    for metric in metrics.events_processed_total.collect():
        for sample in metric.samples:
            if sample.name == "edr_events_processed_total":
                events_processed += int(sample.value)
    for metric in metrics.events_dropped_total.collect():
        for sample in metric.samples:
            if sample.name == "edr_events_dropped_total":
                events_dropped += int(sample.value)

    return {
        "agent_status": "paused" if _state["paused"] else "running",
        "uptime_seconds": round(uptime, 1),
        "collector_sources": _state.get("collector_names", []),
        "events_processed": events_processed,
        "events_dropped": events_dropped,
        "events_per_second": round(events_processed / max(uptime, 1), 1),
        "queue_depth": queue.count_unprocessed(),
    }


@app.get("/api/findings")
async def get_findings(
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List findings with optional severity filter."""
    queue = _get_queue()
    all_findings = queue.get_findings(limit=limit + offset, severity=severity)
    paginated = all_findings[offset : offset + limit]

    return {
        "findings": [_serialize_finding(f) for f in paginated],
        "total": len(all_findings),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/findings/{finding_id}")
async def get_finding_detail(finding_id: str):
    """Full detail for a single finding."""
    queue = _get_queue()
    findings = queue.get_findings(limit=500)
    for f in findings:
        if f.id == finding_id:
            return _serialize_finding(f)
    raise HTTPException(404, "Finding not found")


@app.get("/api/graph/process-tree/{pid}")
async def get_process_tree(pid: int):
    """Process tree for a given PID (ancestors + descendants with activity)."""
    conn = _get_conn()
    tree = gq.get_process_tree(conn, pid)
    if tree is None:
        return {"root": []}
    return tree


@app.get("/api/graph/network/{pid}")
async def get_network_graph(pid: int):
    """Network footprint for a process."""
    conn = _get_conn()
    footprint = gq.get_process_network_footprint(conn, pid)

    # Get process info
    process = {}
    try:
        result = conn.execute(
            "MATCH (p:Process {pid: $pid}) RETURN p.name, p.pid, p.cmd_line",
            {"pid": pid},
        )
        if result.has_next():
            row = result.get_next()
            process = {"name": row[0], "pid": row[1], "cmd_line": row[2]}
    except Exception:
        pass

    return {"process": process, **footprint}


@app.get("/api/graph/attack-chain/{pid}")
async def get_attack_chain(pid: int):
    """Full attack chain context for a PID."""
    conn = _get_conn()
    chain = gq.build_attack_chain(conn, pid)

    # Enrich file_activity from findings IOCs for this PID
    # and include findings as assessment summary
    try:
        queue = _get_queue()
        findings = queue.get_findings_for_pids([pid])
        existing_paths = {f.get("file_path", "").lower() for f in chain.get("file_activity", [])}
        chain["findings"] = []
        for f in findings:
            for file_path in (f.iocs or {}).get("files", []):
                if file_path and str(file_path).lower() not in existing_paths:
                    existing_paths.add(str(file_path).lower())
                    chain["file_activity"].append({
                        "file_path": str(file_path),
                        "operation": "REFERENCED",
                        "timestamp": f.timestamp.isoformat(),
                        "source": f"Finding: {f.title}",
                    })
            chain["findings"].append({
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "timestamp": f.timestamp.isoformat(),
                "affected_entities": f.affected_entities,
                "evidence_event_ids": f.evidence_event_ids,
                "iocs": f.iocs or {},
            })
    except Exception:
        pass

    return chain


@app.get("/api/graph/ioc-chain/{finding_id}")
async def get_ioc_chain(finding_id: str):
    """Build an attack-chain-compatible view for IOC/feed findings without PIDs.

    Uses the finding's own chain data + graph domain resolution to produce
    a structure that renderChain() can display.
    """
    queue = _get_queue()
    finding = None
    for f in queue.get_findings(limit=500):
        if f.id == finding_id:
            finding = f
            break
    if finding is None:
        raise HTTPException(404, "Finding not found")

    conn = _get_conn()
    iocs = finding.iocs or {}
    chain = finding.chain or []

    # Build process chain from finding's chain steps
    process_chain = []
    for step in chain:
        s = step if isinstance(step, dict) else {
            "entity_type": step.entity_type,
            "entity_id": step.entity_id,
            "entity_name": step.entity_name,
            "pid": getattr(step, "pid", None),
        }
        if s.get("entity_type") == "process":
            process_chain.append({
                "name": s.get("entity_name", "?"),
                "pid": s.get("pid") or 0,
                "type": "process",
            })

    # Gather domain resolution data from graph
    domains_data = []
    for domain in iocs.get("domains", []):
        history = gq.get_domain_resolution_history(conn, domain)
        domains_data.append({
            "name": domain,
            "resolved_ips": history,
        })

    # Gather IP enrichment from graph
    ips_data = []
    for ip in iocs.get("ips", []):
        try:
            result = conn.execute(
                "MATCH (i:IP {address: $ip}) "
                "RETURN i.address, i.classification, i.provider_name, "
                "i.isp, i.country, i.reverse_dns",
                {"ip": ip},
            )
            if result.has_next():
                row = result.get_next()
                ips_data.append({
                    "address": row[0],
                    "classification": row[1] or "unclassified",
                    "provider_name": row[2] or "",
                    "isp": row[3] or "",
                    "country": row[4] or "",
                    "reverse_dns": row[5] or "",
                })
            else:
                ips_data.append({"address": ip, "classification": "unclassified"})
        except Exception:
            ips_data.append({"address": ip, "classification": "unclassified"})

    # Build attack-chain-compatible response
    return {
        "process_chain": process_chain,
        "target_process": process_chain[0] if process_chain else None,
        "child_processes": [],
        "network_footprint": {
            "domains": [{"name": d["name"], "is_dga_candidate": False} for d in domains_data],
            "ips": [{"address": ip["address"], "port": None,
                     "classification": ip.get("classification", ""),
                     "provider_name": ip.get("provider_name", "")}
                    for ip in ips_data],
            "listening_ports": [],
        },
        "file_activity": [],
        "risk_indicators": [],
        "findings": [{
            "id": finding.id,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "timestamp": finding.timestamp.isoformat(),
            "affected_entities": finding.affected_entities,
            "evidence_event_ids": finding.evidence_event_ids,
            "iocs": iocs,
        }],
        # Extra fields for IOC-centric view
        "ioc_domains": domains_data,
        "ioc_ips": ips_data,
    }


@app.get("/api/graph/ioc-summary")
async def get_ioc_summary():
    """Global IOC/IOA summary: all domains, external IPs, and file activity.

    Also cross-references with findings IOCs to show which findings mention each indicator.
    """
    conn = _get_conn()
    result = gq.get_ioc_summary(conn)

    # Cross-reference IOCs with findings via two strategies:
    # 1. PID-based: if a finding's affected_pids overlap with the PIDs that
    #    connected to / resolved / created the IOC, link them.
    # 2. Value-based: if the finding's iocs field explicitly names the indicator.
    try:
        queue = _get_queue()
        findings = queue.get_findings(limit=200)

        # Build PID -> finding info lookup
        pid_findings: dict[int, list[dict]] = {}
        # Build IOC value -> finding info lookup
        ioc_findings: dict[str, list[dict]] = {}
        for f in findings:
            f_info = {
                "title": f.title,
                "id": f.id,
                "pids": [p for p in (f.affected_pids or []) if p and p > 0],
            }
            for pid in (f.affected_pids or []):
                if pid and pid > 0:
                    pid_findings.setdefault(pid, []).append(f_info)
            for key in ("domains", "ips", "files", "urls"):
                for val in (f.iocs or {}).get(key, []):
                    ioc_findings.setdefault(str(val).lower(), []).append(f_info)

        def _find_refs(pids: list, value_key: str | None = None) -> list[dict]:
            """Collect unique finding refs for a set of PIDs and/or IOC value."""
            refs: list[dict] = []
            seen: set[str] = set()
            for pid in (pids or []):
                if pid and pid > 0:
                    for fi in pid_findings.get(pid, []):
                        if fi["id"] not in seen:
                            seen.add(fi["id"])
                            refs.append(fi)
            if value_key:
                for fi in ioc_findings.get(value_key.lower(), []):
                    if fi["id"] not in seen:
                        seen.add(fi["id"])
                        refs.append(fi)
            return refs

        for ip in result.get("external_ips", []):
            ip["findings"] = _find_refs(ip.get("connected_by_pids"), ip.get("address"))

        # Build IP -> finding refs from the IP results so domains can
        # inherit findings transitively: Domain→resolves_to→IP→connected_by→Process→Finding
        ip_to_findings: dict[str, list[dict]] = {}
        for ip in result.get("external_ips", []):
            if ip.get("findings"):
                ip_to_findings[ip["address"]] = ip["findings"]

        for d in result.get("domains", []):
            refs = _find_refs(d.get("resolved_by_pids"), d.get("name"))
            # Also inherit findings from IPs this domain resolves to
            seen = {r["id"] for r in refs}
            for resolved_ip in (d.get("resolved_ips") or []):
                for r in ip_to_findings.get(resolved_ip, []):
                    if r["id"] not in seen:
                        seen.add(r["id"])
                        refs.append(r)
            d["findings"] = refs

        # Cross-reference files with findings
        existing_file_paths = {f.get("path", "").lower() for f in result.get("files", [])}
        for f in result.get("files", []):
            f["findings"] = _find_refs(f.get("by_pids"), f.get("path"))

        # Add files mentioned in findings IOCs that aren't already in the graph
        for f_obj in findings:
            for file_path in (f_obj.iocs or {}).get("files", []):
                if file_path and str(file_path).lower() not in existing_file_paths:
                    existing_file_paths.add(str(file_path).lower())
                    # Build PID list from this finding's affected_pids
                    f_pids = [p for p in (f_obj.affected_pids or []) if p and p > 0]
                    result["files"].append({
                        "path": str(file_path),
                        "operation": "REFERENCED",
                        "by_processes": [],
                        "by_pids": f_pids,
                        "timestamp": f_obj.timestamp.isoformat(),
                        "findings": [{
                            "title": f_obj.title,
                            "id": f_obj.id,
                            "pids": f_pids,
                        }],
                    })
    except Exception:
        pass

    return result


@app.get("/api/graph/process-by-name/{name}")
async def get_process_by_name(name: str):
    """Look up Process nodes by name. Returns up to 5 matches with PID and cmd_line."""
    conn = _get_conn()
    try:
        result = conn.execute(
            "MATCH (p:Process {name: $name}) "
            "RETURN p.pid, p.name, p.cmd_line "
            "ORDER BY p.start_time DESC LIMIT 5",
            {"name": name},
        )
        matches = []
        while result.has_next():
            row = result.get_next()
            matches.append({"pid": row[0], "name": row[1], "cmd_line": row[2]})
        return {"matches": matches}
    except Exception:
        return {"matches": []}


@app.get("/api/graph/stats")
async def get_graph_stats():
    """Node and edge counts."""
    conn = _get_conn()
    nodes = {}
    edges = {}

    for table in ["User", "Process", "IP", "Domain", "File", "RegistryKey"]:
        try:
            r = conn.execute(f"MATCH (n:{table}) RETURN COUNT(n)")
            nodes[table] = r.get_next()[0] if r.has_next() else 0
        except Exception:
            nodes[table] = 0

    for table in [
        "SPAWNED", "CONNECTED_TO", "RESOLVED", "RESOLVES_TO",
        "CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE",
        "CREATED_REG", "MODIFIED_REG", "DELETED_REG",
    ]:
        try:
            r = conn.execute(f"MATCH ()-[e:{table}]->() RETURN COUNT(e)")
            edges[table] = r.get_next()[0] if r.has_next() else 0
        except Exception:
            edges[table] = 0

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": sum(nodes.values()),
        "total_edges": sum(edges.values()),
    }


@app.get("/api/metrics")
async def get_metrics_json():
    """Prometheus metrics as JSON."""
    result = {}
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            key = sample.name
            labels = sample.labels
            if labels:
                key += "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"
            result[key] = sample.value
    return result


@app.get("/api/audit-trail")
async def get_audit_trail(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Response action audit trail."""
    import sqlite3

    settings = _get_settings()
    if not settings:
        return {"trail": [], "total": 0}

    try:
        conn = sqlite3.connect(str(settings.db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM response_audit ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM response_audit").fetchone()[0]
        conn.close()

        return {
            "trail": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except Exception:
        return {"trail": [], "total": 0}


@app.get("/api/events/recent")
async def get_recent_events(
    limit: int = Query(100, ge=1, le=1000),
    source: str = Query("all"),
):
    """Most recent events from the processing pipeline."""
    with recent_events_lock:
        events = list(recent_events)

    if source != "all":
        events = [e for e in events if e.get("source") == source]

    return {"events": events[:limit], "total": len(events)}


@app.post("/api/response/approve/{response_id}")
async def approve_response(response_id: str, body: dict):
    """Approve or deny a pending response action."""
    action = body.get("action")
    if action not in ("approve", "deny"):
        raise HTTPException(400, "action must be 'approve' or 'deny'")

    settings = _get_settings()
    if not settings:
        raise HTTPException(503, "Settings not initialized")

    import sqlite3

    conn = sqlite3.connect(str(settings.db_path))
    conn.row_factory = sqlite3.Row

    row = conn.execute(
        "SELECT * FROM response_audit WHERE response_id = ?",
        (response_id,),
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(404, "Response record not found")

    if row["approval_status"] != "pending":
        conn.close()
        raise HTTPException(400, f"Response is not pending (status: {row['approval_status']})")

    new_status = "approved" if action == "approve" else "denied"
    conn.execute(
        "UPDATE response_audit SET approval_status = ?, approved_by = 'dashboard_user' "
        "WHERE response_id = ?",
        (new_status, response_id),
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "response_id": response_id, "approval_status": new_status}


@app.get("/api/connections/{pid}")
async def get_connections(pid: int, hours: int = Query(1, ge=1, le=168)):
    """Connection metadata for a process within a time window."""
    import sqlite3

    settings = _get_settings()
    if not settings:
        return {"connections": [], "pid": pid}

    try:
        from agent.collectors.connection_metadata import (
            get_connection_metadata,
        )

        conn = sqlite3.connect(str(settings.db_path))
        conn.row_factory = sqlite3.Row

        # Check if table exists
        table_check = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='connection_metadata'"
        ).fetchone()
        if not table_check:
            conn.close()
            return {"connections": [], "pid": pid, "message": "No connection metadata table"}

        rows = get_connection_metadata(conn, pid=pid if pid > 0 else None, hours=hours)
        conn.close()

        return {"connections": rows, "pid": pid, "hours": hours, "count": len(rows)}
    except Exception:
        logger.debug("Failed to get connection metadata", exc_info=True)
        return {"connections": [], "pid": pid, "error": "Query failed"}


@app.post("/api/pause")
async def pause_agent():
    """Pause the processing pipeline. Events still collect but aren't processed."""
    _state["paused"] = True
    return {"status": "ok", "paused": True}


@app.post("/api/resume")
async def resume_agent():
    """Resume the processing pipeline."""
    _state["paused"] = False
    return {"status": "ok", "paused": False}


@app.get("/api/settings")
async def get_settings_info():
    """Current agent configuration (read-only)."""
    settings = _get_settings()
    if not settings:
        return {}
    return {
        "data_dir": str(settings.data_dir),
        "collector_poll_interval": settings.collector_poll_interval,
        "processor_poll_interval": settings.processor_poll_interval,
        "analyzer_interval": settings.analyzer_interval,
        "processor_batch_size": settings.processor_batch_size,
        "dashboard_port": settings.dashboard_port,
        "metrics_port": settings.metrics_port,
        "dga_entropy_threshold": settings.dga_entropy_threshold,
        "dga_score_threshold": settings.dga_score_threshold,
        "dga_allowlist": settings.dga_allowlist,
        "auto_respond": settings.auto_respond,
        "auto_terminate": settings.auto_terminate,
        "watchdog_enabled": settings.watchdog_enabled,
        "tamper_check_enabled": settings.tamper_check_enabled,
        "ioc_feeds_enabled": settings.ioc_feeds_enabled,
        "ioc_feeds_refresh_hours": settings.ioc_feeds_refresh_hours,
        "ioc_exclusion_patterns": settings.ioc_exclusion_patterns,
        "investigation_tools_enabled": settings.investigation_tools_enabled,
    }


@app.get("/api/intel/ioc-stats")
async def get_ioc_stats():
    """IOC feed database statistics."""
    ioc_db = _state.get("ioc_db")
    if ioc_db is None:
        return {"enabled": False}
    stats = ioc_db.stats()
    stats["enabled"] = True
    return stats


# ── Response Mode / Baseline / Allowlist / Network Controls ───────────────


@app.get("/api/response/mode")
async def get_response_mode():
    """Current response mode."""
    engine = _state.get("response_engine")
    if engine is None:
        return {"mode": "passive"}
    return {"mode": engine.response_mode}


@app.post("/api/response/mode")
async def set_response_mode(body: dict):
    """Switch response mode."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    mode = body.get("mode", "")
    try:
        engine.set_mode(mode)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"mode": engine.response_mode}


@app.get("/api/response/baseline/stats")
async def get_baseline_stats():
    """Baseline statistics."""
    baseline = _state.get("baseline")
    if baseline is None:
        return {"total": 0, "by_type": {}, "earliest": None, "latest": None}
    return baseline.stats()


@app.get("/api/response/baseline")
async def get_baseline_entries(limit: int = Query(100, ge=1, le=1000)):
    """Baseline entries."""
    baseline = _state.get("baseline")
    if baseline is None:
        return {"entries": []}
    return {"entries": baseline.get_entries(limit=limit)}


@app.post("/api/response/baseline/clear")
async def clear_baseline():
    """Clear the behavior baseline."""
    baseline = _state.get("baseline")
    if baseline is None:
        raise HTTPException(503, "Baseline not initialized")
    baseline.clear()
    return {"status": "ok"}


@app.get("/api/response/allowlist")
async def get_allowlist():
    """Get all allowlist rules."""
    allowlist = _state.get("allowlist")
    if allowlist is None:
        return {"rules": []}
    return {"rules": allowlist.get_rules()}


@app.post("/api/response/allowlist")
async def add_allowlist_rule(body: dict):
    """Add an allowlist rule."""
    allowlist = _state.get("allowlist")
    if allowlist is None:
        raise HTTPException(503, "Allowlist not initialized")
    rule_type = body.get("rule_type", "")
    pattern = body.get("pattern", "")
    description = body.get("description", "")
    chain_filter = body.get("chain_filter", "")
    if not rule_type or not pattern:
        raise HTTPException(400, "rule_type and pattern are required")
    try:
        rule_id = allowlist.add_rule(rule_type, pattern, description, chain_filter=chain_filter)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Database error: {e}")
    return {"status": "ok", "rule_id": rule_id}


@app.delete("/api/response/allowlist/{rule_id}")
async def delete_allowlist_rule(rule_id: int):
    """Delete an allowlist rule."""
    allowlist = _state.get("allowlist")
    if allowlist is None:
        raise HTTPException(503, "Allowlist not initialized")
    if not allowlist.remove_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    return {"status": "ok"}


@app.get("/api/response/blocklist")
async def get_blocklist():
    """Get all blocklist rules."""
    blocklist = _state.get("blocklist")
    if blocklist is None:
        return {"rules": []}
    return {"rules": blocklist.get_rules()}


@app.post("/api/response/blocklist")
async def add_blocklist_rule(body: dict):
    """Add a blocklist rule."""
    blocklist = _state.get("blocklist")
    if blocklist is None:
        raise HTTPException(503, "Blocklist not initialized")
    rule_type = body.get("rule_type", "")
    pattern = body.get("pattern", "")
    description = body.get("description", "")
    chain_filter = body.get("chain_filter", "")
    if not rule_type or not pattern:
        raise HTTPException(400, "rule_type and pattern are required")
    try:
        rule_id = blocklist.add_rule(rule_type, pattern, description, chain_filter=chain_filter)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Database error: {e}")
    return {"status": "ok", "rule_id": rule_id}


@app.delete("/api/response/blocklist/{rule_id}")
async def delete_blocklist_rule(rule_id: int):
    """Delete a blocklist rule."""
    blocklist = _state.get("blocklist")
    if blocklist is None:
        raise HTTPException(503, "Blocklist not initialized")
    if not blocklist.remove_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    return {"status": "ok"}


@app.post("/api/response/block-connection")
async def block_connection(body: dict):
    """Block traffic to a specific IP:port."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    ip = body.get("ip", "")
    port = body.get("port")
    if not ip:
        raise HTTPException(400, "ip is required")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")
    if port is not None:
        port = int(port)
        if not (1 <= port <= 65535):
            raise HTTPException(400, f"Invalid port: {port}")
    outcome = engine.network_isolator.block_connection(ip, port)
    return {"status": outcome.result.value, "detail": outcome.detail}


@app.post("/api/response/unblock-connection")
async def unblock_connection(body: dict):
    """Remove a connection block."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    ip = body.get("ip", "")
    port = body.get("port")
    if not ip:
        raise HTTPException(400, "ip is required")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip!r}")
    if port is not None:
        port = int(port)
        if not (1 <= port <= 65535):
            raise HTTPException(400, f"Invalid port: {port}")
    outcome = engine.network_isolator.unblock_connection(ip, port)
    return {"status": outcome.result.value, "detail": outcome.detail}


@app.post("/api/response/sinkhole")
async def sinkhole_domain(body: dict):
    """Sinkhole a domain to 127.0.0.1."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    if engine.dns_sinkhole is None:
        raise HTTPException(503, "DNS sinkhole not initialized")
    domain = body.get("domain", "")
    if not domain:
        raise HTTPException(400, "domain is required")
    outcome = engine.dns_sinkhole.sinkhole(domain)
    return {"status": outcome.result, "detail": outcome.detail}


@app.post("/api/response/unsinkhole")
async def unsinkhole_domain(body: dict):
    """Remove a domain sinkhole."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    if engine.dns_sinkhole is None:
        raise HTTPException(503, "DNS sinkhole not initialized")
    domain = body.get("domain", "")
    if not domain:
        raise HTTPException(400, "domain is required")
    outcome = engine.dns_sinkhole.restore(domain)
    return {"status": outcome.result, "detail": outcome.detail}


@app.post("/api/response/panic")
async def activate_panic():
    """Activate panic mode — block ALL network traffic except loopback."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    outcome = engine.network_isolator.panic_isolate()
    return {"status": outcome.result.value, "detail": outcome.detail}


@app.post("/api/response/panic/restore")
async def deactivate_panic():
    """Deactivate panic mode — restore network connectivity."""
    engine = _state.get("response_engine")
    if engine is None:
        raise HTTPException(503, "Response engine not initialized")
    outcome = engine.network_isolator.panic_restore()
    return {"status": outcome.result.value, "detail": outcome.detail}


@app.get("/api/response/network-status")
async def get_network_status():
    """Current network control status."""
    engine = _state.get("response_engine")
    if engine is None:
        return {
            "blocked_connections": [],
            "sinkholed_domains": [],
            "panic_active": False,
            "isolated_pids": [],
        }

    blocked = []
    for (ip, port), rule in engine.network_isolator.blocked_connections.items():
        entry = {"ip": ip, "rule": rule}
        if port is not None:
            entry["port"] = port
        blocked.append(entry)

    sinkholed = []
    if engine.dns_sinkhole:
        sinkholed = sorted(engine.dns_sinkhole.sinkholed_domains)

    return {
        "blocked_connections": blocked,
        "sinkholed_domains": sinkholed,
        "panic_active": engine.network_isolator.panic_active,
        "isolated_pids": sorted(engine.network_isolator.isolated_pids),
    }


# ── Helpers ───────────────────────────────────────────────────────────────


def _serialize_finding(f) -> dict:
    """Convert a SecurityFinding to a JSON-serializable dict."""
    # Filter out PID 0 (system-level collectors like mDNSResponder/FSEvents)
    affected_pids = [p for p in f.affected_pids if p and p > 0]
    return {
        "id": f.id,
        "timestamp": f.timestamp.isoformat(),
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "affected_entities": f.affected_entities,
        "evidence_event_ids": f.evidence_event_ids,
        "recommendation": f.recommendation,
        "affected_pids": affected_pids,
        "chain": [
            {
                "entity_type": s.entity_type,
                "entity_id": s.entity_id,
                "entity_name": s.entity_name,
                "pid": s.pid if s.pid and s.pid > 0 else None,
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            }
            for s in f.chain
        ],
        "iocs": f.iocs if f.iocs else {},
    }


def append_recent_event(event_data: dict) -> None:
    """Called by the processor thread to add an event to the recent buffer."""
    with recent_events_lock:
        recent_events.appendleft(event_data)


def init_dashboard(
    queue: SqliteQueue,
    kuzu_db: kuzu.Database,
    settings,
    collector_names: list[str],
    ioc_db=None,
    response_engine=None,
    baseline=None,
    allowlist=None,
    blocklist=None,
) -> None:
    """Initialize dashboard state. Called once from main.py."""
    _state["queue"] = queue
    _state["kuzu_db"] = kuzu_db
    _state["settings"] = settings
    _state["start_time"] = time.time()
    _state["collector_names"] = collector_names
    _state["ioc_db"] = ioc_db
    _state["response_engine"] = response_engine
    _state["baseline"] = baseline
    _state["allowlist"] = allowlist
    _state["blocklist"] = blocklist


def start_dashboard_server(port: int = 9200) -> threading.Thread:
    """Start uvicorn in a daemon thread. Returns the thread."""
    import uvicorn

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(
        target=server.run,
        daemon=True,
        name="dashboard",
    )
    thread.start()
    logger.info("Dashboard server started on http://127.0.0.1:%d", port)
    return thread
