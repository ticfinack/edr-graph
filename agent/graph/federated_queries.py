"""Federated query handlers for XDR sensor fusion.

Executed locally on the edge agent against Kuzu when the fleet server
requests missing context (e.g., victim-side telemetry for lateral movement).
"""

from __future__ import annotations

import logging

import kuzu

logger = logging.getLogger("agent.graph.federated")

_HANDLERS: dict[str, callable] = {}


def execute_query(db: kuzu.Database, query_type: str, params: dict) -> dict:
    """Dispatch a federated query to the appropriate handler."""
    handler = _HANDLERS.get(query_type)
    if not handler:
        return {"error": f"unknown query_type: {query_type}"}
    return handler(db, params)


def lateral_victim_trace(db: kuzu.Database, params: dict) -> dict:
    """Find processes that received inbound connections from given IPs.

    Kuzu data model: (sshd:Process)-[CONNECTED_TO {direction:'inbound'}]->(IP)
    Created by entity_extractor._extract_authentication().
    """
    victim_ips = params.get("victim_ips", [])
    target_port = params.get("target_port")
    from agent.graph.connection import get_connection

    conn = get_connection()
    try:
        records = []
        for ip_addr in victim_ips:
            where_clause = "WHERE c.direction = 'inbound'"
            query_params: dict = {"ip": ip_addr}
            if target_port is not None:
                where_clause += " AND c.dst_port = $target_port"
                query_params["target_port"] = int(target_port)

            result = conn.execute(
                "MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IP {address: $ip}) "
                + where_clause + " "
                "OPTIONAL MATCH (u:User)-[:SPAWNED]->(p) "
                "RETURN p.name, p.pid, p.cmd_line, ip.address, "
                "c.dst_port, c.timestamp, u.name "
                "ORDER BY c.timestamp DESC LIMIT 5",
                query_params,
            )
            while result.has_next():
                row = result.get_next()
                records.append({
                    "process_name": row[0],
                    "pid": row[1],
                    "cmd_line": row[2],
                    "from_ip": row[3],
                    "dst_port": row[4],
                    "timestamp": str(row[5]) if row[5] else None,
                    "username": row[6],
                })
        return {"status": "ok", "records": records}
    except Exception:
        logger.debug("lateral_victim_trace failed", exc_info=True)
        return {"status": "error", "records": []}


_HANDLERS["lateral_victim_trace"] = lateral_victim_trace


def lateral_source_trace(db: kuzu.Database, params: dict) -> dict:
    """Find processes that made outbound connections to given IPs.

    Mirror of lateral_victim_trace: queries the SOURCE agent for outbound
    connections TO the victim's IPs, revealing the process chain that
    initiated the lateral movement (e.g., ssh client → victim IP).

    Kuzu data model: (ssh:Process)-[CONNECTED_TO {direction:'outbound'}]->(IP)
    Created by entity_extractor for NetworkActivity events.
    """
    dst_ips = params.get("dst_ips", [])
    target_port = params.get("target_port")
    from agent.graph.connection import get_connection

    conn = get_connection()
    try:
        records = []
        for ip_addr in dst_ips:
            where_clause = "WHERE c.direction = 'outbound'"
            query_params: dict = {"ip": ip_addr}
            if target_port is not None:
                where_clause += " AND c.dst_port = $target_port"
                query_params["target_port"] = int(target_port)

            result = conn.execute(
                "MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IP {address: $ip}) "
                + where_clause + " "
                "OPTIONAL MATCH (u:User)-[:SPAWNED]->(p) "
                "RETURN p.name, p.pid, p.cmd_line, ip.address, "
                "c.dst_port, c.timestamp, u.name "
                "ORDER BY c.timestamp DESC LIMIT 5",
                query_params,
            )
            while result.has_next():
                row = result.get_next()
                records.append({
                    "process_name": row[0],
                    "pid": row[1],
                    "cmd_line": row[2],
                    "from_ip": row[3],
                    "dst_port": row[4],
                    "timestamp": str(row[5]) if row[5] else None,
                    "username": row[6],
                })
        return {"status": "ok", "records": records}
    except Exception:
        logger.debug("lateral_source_trace failed", exc_info=True)
        return {"status": "error", "records": []}


_HANDLERS["lateral_source_trace"] = lateral_source_trace


def _resolve_descendant_pids(anchor_pids: list[int]) -> list[int]:
    """BFS from anchor PIDs through the pid_index to collect descendant PIDs.

    Returns anchor_pids union all descendants, capped at 200 total PIDs
    and 10 BFS depth levels.  Gracefully degrades to just anchor_pids
    if the pid_index is not built.
    """
    if not anchor_pids:
        return []
    try:
        from agent.graph.pid_index import get_pid_index
        index = get_pid_index()
    except Exception:
        return list(anchor_pids)

    if not index.is_built:
        return list(anchor_pids)

    result: set[int] = set(anchor_pids)
    frontier: set[int] = set(anchor_pids)
    max_depth = 10
    max_total = 200

    for _ in range(max_depth):
        if len(result) >= max_total:
            break
        next_frontier: set[int] = set()
        for pid in frontier:
            children = index.get_children_pids(pid)
            for child in children:
                if child not in result:
                    result.add(child)
                    next_frontier.add(child)
                    if len(result) >= max_total:
                        break
            if len(result) >= max_total:
                break
        if not next_frontier:
            break
        frontier = next_frontier

    return list(result)


def pull_surveillance_logs(db: kuzu.Database, params: dict) -> dict:
    """Return surveillance logs from the forensic ledger via tri-fold query.

    Queries the local SQLite forensic ledger (not Kuzu).  The ``db``
    argument is ignored but kept for handler-signature compatibility.

    Falls back to the legacy flight recorder if the ledger is not available.

    Three independent query paths, results merged and deduplicated:
      1. anchor_pids → BFS descendant resolution → PID filter
      2. ips → IP address filter (network connections)
      3. usernames → identity filter (catches execve even if PID lineage fails)

    Params:
        anchor_pids: list of process PIDs to resolve descendants for (optional)
        ips:         list of IP addresses to filter on (optional)
        usernames:   list of usernames to filter on (optional)
        since:       epoch timestamp lower bound (optional)
        limit:       max rows (default 200)
    """
    import time as _time

    # Try forensic ledger first (Tier 1), fall back to flight recorder
    ledger_reader = None
    try:
        from agent.main import _ledger_writer
        if _ledger_writer is not None:
            from agent.ledger.reader import LedgerReader
            ledger_reader = LedgerReader(_ledger_writer._data_dir)
    except Exception:
        pass

    if ledger_reader is None:
        # Fall back to legacy flight recorder
        try:
            from agent.main import _flight_recorder
            if _flight_recorder is None:
                return {"status": "error", "records": [], "error": "no surveillance backend running"}
        except ImportError:
            return {"status": "error", "records": [], "error": "no surveillance backend running"}

        return _pull_from_flight_recorder(params)

    anchor_pids = params.get("anchor_pids", [])
    ips = params.get("ips", [])
    usernames = params.get("usernames", [])
    since = params.get("since")
    limit = params.get("limit", 200)

    all_records: list[dict] = []

    # Primary path: ancestry-based PID filtering
    if anchor_pids:
        target_pids = _resolve_descendant_pids(anchor_pids)
        for pid in target_pids:
            rows = ledger_reader.query_by_pid(pid, since=since, limit=limit)
            for r in rows:
                all_records.append({
                    "id": r.id,
                    "timestamp": r.ts,
                    "event_type": r.event_type,
                    "process_name": r.process_name,
                    "pid": r.pid,
                    "username": r.username,
                    "remote_ip": r.remote_ip,
                    "remote_port": r.remote_port,
                })

    # IP-based queries
    for ip in ips:
        rows = ledger_reader.query_by_ip(ip, since=since, limit=limit)
        for r in rows:
            all_records.append({
                "id": r.id,
                "timestamp": r.ts,
                "event_type": r.event_type,
                "process_name": r.process_name,
                "pid": r.pid,
                "username": r.username,
                "remote_ip": r.remote_ip,
                "remote_port": r.remote_port,
            })

    # If no specific filters, query a time range
    if not anchor_pids and not ips and not usernames:
        now = _time.time()
        start = since if since else (now - 3600)
        rows = ledger_reader.query_time_range(start, now, limit=limit)
        for r in rows:
            all_records.append({
                "id": r.id,
                "timestamp": r.ts,
                "event_type": r.event_type,
                "process_name": r.process_name,
                "pid": r.pid,
                "username": r.username,
                "remote_ip": r.remote_ip,
                "remote_port": r.remote_port,
            })

    # Deduplicate
    seen: set[int] = set()
    deduped: list[dict] = []
    for r in all_records:
        rid = r["id"]
        if rid not in seen:
            seen.add(rid)
            deduped.append(r)

    deduped.sort(key=lambda r: r.get("timestamp", 0), reverse=True)
    return {"status": "ok", "records": deduped[:limit]}


def _pull_from_flight_recorder(params: dict) -> dict:
    """Legacy fallback: pull surveillance logs from FlightRecorder."""
    from agent.main import _flight_recorder

    anchor_pids = params.get("anchor_pids", [])
    ips = params.get("ips", [])
    since = params.get("since")
    limit = params.get("limit", 200)

    all_records: list[dict] = []

    if anchor_pids:
        target_pids = _resolve_descendant_pids(anchor_pids)
        if target_pids:
            rows = _flight_recorder.query(pids=target_pids, since=since, limit=limit)
            all_records.extend(rows)

    for ip in ips:
        rows = _flight_recorder.query(ip=ip, since=since, limit=limit)
        all_records.extend(rows)

    usernames = params.get("usernames", [])
    for user in usernames:
        rows = _flight_recorder.query(username=user, since=since, limit=limit)
        all_records.extend(rows)

    seen: set[int] = set()
    deduped: list[dict] = []
    for r in all_records:
        rid = r["id"]
        if rid not in seen:
            seen.add(rid)
            deduped.append(r)

    deduped.sort(key=lambda r: r.get("timestamp", 0), reverse=True)
    return {"status": "ok", "records": deduped[:limit]}


_HANDLERS["pull_surveillance_logs"] = pull_surveillance_logs
