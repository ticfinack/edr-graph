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

    Tries Kuzu first (CONNECTED_TO edges), falls back to the forensic
    ledger when Kuzu is unavailable (e.g. warm graph not built yet).
    """
    victim_ips = params.get("victim_ips", [])
    target_port = params.get("target_port")

    try:
        from agent.graph.connection import get_connection
        conn = get_connection()

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
        if records:
            return {"status": "ok", "records": records}
    except Exception:
        logger.debug("lateral_victim_trace Kuzu query failed, trying ledger", exc_info=True)

    # Fallback: query the forensic ledger for network events from victim IPs
    finding_ts = params.get("finding_ts")
    return _trace_from_ledger(victim_ips, direction="inbound", target_port=target_port, finding_ts=finding_ts)


_HANDLERS["lateral_victim_trace"] = lateral_victim_trace


def lateral_source_trace(db: kuzu.Database, params: dict) -> dict:
    """Find processes that made outbound connections to given IPs.

    Mirror of lateral_victim_trace: queries the SOURCE agent for outbound
    connections TO the victim's IPs, revealing the process chain that
    initiated the lateral movement (e.g., ssh client → victim IP).

    Tries Kuzu first, falls back to the forensic ledger.
    """
    dst_ips = params.get("dst_ips", [])
    target_port = params.get("target_port")

    try:
        from agent.graph.connection import get_connection
        conn = get_connection()

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
        if records:
            return {"status": "ok", "records": records}
    except Exception:
        logger.debug("lateral_source_trace Kuzu query failed, trying ledger", exc_info=True)

    # Fallback: query the forensic ledger for network events to dst IPs
    return _trace_from_ledger(dst_ips, direction="outbound", target_port=target_port)


_HANDLERS["lateral_source_trace"] = lateral_source_trace


def _trace_from_ledger(
    ips: list[str],
    direction: str = "inbound",
    target_port: int | None = None,
    finding_ts: float | None = None,
) -> dict:
    """Two-phase ledger trace: find anchor process via IP, then descendants.

    Phase 1: Query NetworkActivity events for the IPs (these have PIDs,
             unlike Authentication events which only have usernames).
             When finding_ts is provided, narrows to the single anchor
             process whose first network event is closest to (but before)
             the finding timestamp.
    Phase 2: Resolve child processes of the anchor PID via pid_index,
             then fetch their recent activity from the ledger.

    Returns records in the same format as the Kuzu-based trace handlers.
    """
    import sqlite3 as _sqlite3

    ledger_path = None
    try:
        from agent.main import _ledger_writer
        if _ledger_writer is not None:
            ledger_path = _ledger_writer._data_dir / "forensic_ledger.db"
    except Exception:
        pass

    if ledger_path is None or not ledger_path.exists():
        return {"status": "ok", "records": []}

    conn = _sqlite3.connect(str(ledger_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA query_only=ON")
    conn.row_factory = _sqlite3.Row
    try:
        records: list[dict] = []
        anchor_pids: set[int] = set()

        # ── Phase 1: Find anchor processes via NetworkActivity ──
        # GROUP BY pid to avoid duplicate rows (same pid, different timestamps).
        # When finding_ts is available, use a 24h window ending at finding_ts
        # and pick the EARLIEST session (most likely the original connection).
        ts_filter = ""
        ts_params: tuple = ()
        if finding_ts:
            f_ts = float(finding_ts)
            ts_filter = " AND ts >= ? AND ts <= ? "
            ts_params = (f_ts - 86400, f_ts)
        for ip_addr in ips:
            rows = conn.execute(
                "SELECT pid, process_name, username, remote_ip, remote_port, "
                "MIN(ts) as ts "
                "FROM forensic_ledger "
                "WHERE remote_ip = ? AND event_type = 'NetworkActivity' AND pid IS NOT NULL "
                + ts_filter +
                "GROUP BY pid "
                "ORDER BY ts ASC LIMIT 1",
                (ip_addr,) + ts_params,
            ).fetchall()
            for r in rows:
                pid = r["pid"]
                anchor_pids.add(pid)
                # Use proc.create_time() for consistent ordering with descendants
                cmd_line = ""
                create_ts = r["ts"]
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    cmd_line = " ".join(proc.cmdline()[:4]) if proc.cmdline() else ""
                    create_ts = proc.create_time()
                except Exception:
                    pass
                records.append({
                    "process_name": r["process_name"],
                    "pid": pid,
                    "cmd_line": cmd_line,
                    "from_ip": r["remote_ip"] or ip_addr,
                    "dst_port": r["remote_port"],
                    "timestamp": str(create_ts) if create_ts else None,
                    "username": r["username"],
                })

        # ── Phase 2: Resolve descendants and their activity ──
        if anchor_pids:
            # Try pid_index first (fast, in-memory), fall back to OS /proc
            child_pids = _resolve_descendant_pids(list(anchor_pids))
            descendant_pids = [p for p in child_pids if p not in anchor_pids]

            # If pid_index found nothing, try OS-level process tree
            if not descendant_pids:
                descendant_pids = _resolve_children_from_os(list(anchor_pids))

            for pid in descendant_pids[:20]:
                rows = conn.execute(
                    "SELECT pid, process_name, username, remote_ip, remote_port, "
                    "MIN(ts) as ts "
                    "FROM forensic_ledger "
                    "WHERE pid = ? AND event_type = 'ProcessActivity' "
                    "ORDER BY ts ASC LIMIT 1",
                    (pid,),
                ).fetchall()
                if rows and rows[0]["pid"] is not None:
                    r = rows[0]
                    # Try to get cmd_line from OS
                    cmd_line = ""
                    try:
                        import psutil
                        proc = psutil.Process(pid)
                        cmd_line = " ".join(proc.cmdline()[:4]) if proc.cmdline() else ""
                    except Exception:
                        pass
                    records.append({
                        "process_name": r["process_name"],
                        "pid": r["pid"],
                        "cmd_line": cmd_line,
                        "from_ip": r["remote_ip"] or "",
                        "dst_port": r["remote_port"],
                        "timestamp": str(r["ts"]) if r["ts"] else None,
                        "username": r["username"],
                    })
                else:
                    # Process exists but no ledger events — read from /proc
                    info = _read_proc_info(pid)
                    if info:
                        records.append(info)

        # ── Fallback: If no NetworkActivity, use Authentication events ──
        if not records:
            for ip_addr in ips:
                rows = conn.execute(
                    "SELECT process_name, pid, username, remote_ip, remote_port, ts "
                    "FROM forensic_ledger "
                    "WHERE remote_ip = ? "
                    "ORDER BY ts DESC LIMIT 5",
                    (ip_addr,),
                ).fetchall()
                for r in rows:
                    records.append({
                        "process_name": r["process_name"],
                        "pid": r["pid"],
                        "cmd_line": "",
                        "from_ip": r["remote_ip"] or ip_addr,
                        "dst_port": r["remote_port"],
                        "timestamp": str(r["ts"]) if r["ts"] else None,
                        "username": r["username"],
                    })

        records.sort(key=lambda x: float(x.get("timestamp") or 0), reverse=True)
        return {"status": "ok", "records": records[:15]}
    finally:
        conn.close()


def _resolve_children_from_os(anchor_pids: list[int], max_depth: int = 3) -> list[int]:
    """Walk the OS process tree (via psutil) to find descendants.

    Used when the pid_index doesn't have the mapping (e.g., long-lived
    processes outside the warm graph window).
    """
    try:
        import psutil
    except ImportError:
        return []

    result: list[int] = []
    frontier = list(anchor_pids)
    seen = set(anchor_pids)

    for _ in range(max_depth):
        next_frontier: list[int] = []
        for pid in frontier:
            try:
                proc = psutil.Process(pid)
                for child in proc.children(recursive=False):
                    if child.pid not in seen:
                        seen.add(child.pid)
                        result.append(child.pid)
                        next_frontier.append(child.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not next_frontier:
            break
        frontier = next_frontier

    return result


def _read_proc_info(pid: int) -> dict | None:
    """Read basic process info from the OS for a live process."""
    try:
        import psutil
        proc = psutil.Process(pid)
        return {
            "process_name": proc.name(),
            "pid": pid,
            "cmd_line": " ".join(proc.cmdline()[:3]) if proc.cmdline() else "",
            "from_ip": "",
            "dst_port": None,
            "timestamp": str(proc.create_time()),
            "username": proc.username(),
        }
    except Exception:
        return None


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


def pull_ocsf_ledger(db: kuzu.Database, params: dict) -> dict:
    """Return OCSF-native evidence from the forensic ledger.

    Same query structure as pull_surveillance_logs (tri-fold: PIDs, IPs,
    usernames) but includes the raw ocsf_json field for each record.
    """
    import time as _time

    ledger_reader = None
    try:
        from agent.main import _ledger_writer
        if _ledger_writer is not None:
            from agent.ledger.reader import LedgerReader
            ledger_reader = LedgerReader(_ledger_writer._data_dir)
    except Exception:
        pass

    if ledger_reader is None:
        return {"status": "error", "records": [], "error": "no ledger available"}

    anchor_pids = params.get("anchor_pids", [])
    ips = params.get("ips", [])
    usernames = params.get("usernames", [])
    since = params.get("since")
    limit = params.get("limit", 300)

    all_records: list[dict] = []

    if anchor_pids:
        target_pids = _resolve_descendant_pids(anchor_pids)
        for pid in target_pids:
            rows = ledger_reader.query_by_pid(pid, since=since, limit=limit)
            for r in rows:
                all_records.append({
                    "id": r.id,
                    "timestamp": r.ts,
                    "event_type": r.event_type,
                    "ocsf_json": r.ocsf_json if hasattr(r, "ocsf_json") else "{}",
                    "process_name": r.process_name,
                    "pid": r.pid,
                    "username": r.username,
                })

    for ip in ips:
        rows = ledger_reader.query_by_ip(ip, since=since, limit=limit)
        for r in rows:
            all_records.append({
                "id": r.id,
                "timestamp": r.ts,
                "event_type": r.event_type,
                "ocsf_json": r.ocsf_json if hasattr(r, "ocsf_json") else "{}",
                "process_name": r.process_name,
                "pid": r.pid,
                "username": r.username,
            })

    for user in usernames:
        rows = ledger_reader.query_by_username(user, since=since, limit=limit) if hasattr(ledger_reader, "query_by_username") else []
        for r in rows:
            all_records.append({
                "id": r.id,
                "timestamp": r.ts,
                "event_type": r.event_type,
                "ocsf_json": r.ocsf_json if hasattr(r, "ocsf_json") else "{}",
                "process_name": r.process_name,
                "pid": r.pid,
                "username": r.username,
            })

    if not anchor_pids and not ips and not usernames:
        now = _time.time()
        start = since if since else (now - 3600)
        rows = ledger_reader.query_time_range(start, now, limit=limit)
        for r in rows:
            all_records.append({
                "id": r.id,
                "timestamp": r.ts,
                "event_type": r.event_type,
                "ocsf_json": r.ocsf_json if hasattr(r, "ocsf_json") else "{}",
                "process_name": r.process_name,
                "pid": r.pid,
                "username": r.username,
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


_HANDLERS["pull_ocsf_ledger"] = pull_ocsf_ledger
