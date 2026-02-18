"""FastAPI dashboard backend.

Serves the web dashboard UI and REST API endpoints for status, findings,
graph queries, events, and audit trail. Runs inside the agent process as
a uvicorn thread to avoid Kuzu concurrent reader issues.

Binds to 127.0.0.1 only (localhost). No authentication for v1.
# TODO: Add authentication if dashboard is exposed beyond localhost.
"""

from __future__ import annotations

import collections
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import kuzu
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
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
    return gq.build_attack_chain(conn, pid)


@app.get("/api/graph/ioc-summary")
async def get_ioc_summary():
    """Global IOC/IOA summary: all domains, external IPs, and file activity.

    Also cross-references with findings IOCs to show which findings mention each indicator.
    """
    conn = _get_conn()
    result = gq.get_ioc_summary(conn)

    # Cross-reference with findings IOCs
    try:
        queue = _get_queue()
        findings = queue.get_findings(limit=200)
        # Build lookup: ioc_value -> list of finding titles
        ioc_findings: dict[str, list[str]] = {}
        for f in findings:
            iocs = f.iocs or {}
            for key in ("domains", "ips", "files", "urls"):
                for val in iocs.get(key, []):
                    v = str(val).lower()
                    if v not in ioc_findings:
                        ioc_findings[v] = []
                    ioc_findings[v].append(f.title)

        # Annotate graph IOCs with finding references
        for d in result.get("domains", []):
            d["findings"] = ioc_findings.get(d["name"].lower(), [])
        for ip in result.get("external_ips", []):
            ip["findings"] = ioc_findings.get(ip["address"].lower(), [])
        for f in result.get("files", []):
            f["findings"] = ioc_findings.get(f["path"].lower(), [])
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
    from agent.response.engine import ResponseAuditLog
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
) -> None:
    """Initialize dashboard state. Called once from main.py."""
    _state["queue"] = queue
    _state["kuzu_db"] = kuzu_db
    _state["settings"] = settings
    _state["start_time"] = time.time()
    _state["collector_names"] = collector_names


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
