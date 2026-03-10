"""Reusable graph traversal functions for attack chain building."""

from __future__ import annotations

import contextlib
import logging
import socket
import time
from typing import Generator

import kuzu

from agent import metrics
from agent.graph.pid_index import get_pid_index

logger = logging.getLogger(__name__)

# ── Read-only ancestry fallbacks (ledger + live OS) ──────────────────────


def _query_process_from_ledger(pid: int, event_ts: float | None = None) -> dict | None:
    """Fallback: look up a process by PID in the forensic ledger.

    Queries for the most recent record matching *pid* (any event type).
    When *event_ts* is provided, only considers records at or before that time.
    Returns a dict matching the Kuzu output schema, or None.
    """
    try:
        from agent.main import _ledger_writer
        if _ledger_writer is None:
            return None
        from agent.ledger.reader import LedgerReader
        reader = LedgerReader(_ledger_writer._data_dir)
        rows = reader.query_by_pid(pid, limit=1)
        if not rows:
            return None
        r = rows[0]
        # Temporal filter: skip if the ledger row is after event_ts
        if event_ts is not None and r.ts > event_ts:
            return None
        hostname = r.hostname or socket.gethostname()
        return {
            "id": f"{hostname}:{pid}:{int(r.ts)}",
            "name": r.process_name or "",
            "pid": pid,
            "cmd_line": "",
            "exe_path": "",
            "hostname": hostname,
            "parent_pid": r.parent_pid,
            "bundle_id": "",
            "code_signed": None,
            "signing_authority": "",
            "_fallback": "ledger",
        }
    except Exception:
        logger.debug("Ledger fallback failed for pid %d", pid, exc_info=True)
        return None


def _query_process_from_os(pid: int, event_ts: float | None = None) -> dict | None:
    """Fallback: look up a live process by PID via psutil.

    When *event_ts* is provided, rejects the process if its create_time
    is after event_ts (wrong PID incarnation).
    Returns a dict matching the Kuzu output schema, or None if the process
    is dead or inaccessible.
    """
    try:
        import psutil
        p = psutil.Process(pid)
        name = p.name()
        cmd_line = ""
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            cmd_line = " ".join(p.cmdline())
        exe_path = ""
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            exe_path = p.exe() or ""
        ppid = 0
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            ppid = p.ppid()
        uid = 0
        username = ""
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            uid = p.uids().real
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            username = p.username() or ""
        create_time = 0
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            create_time = int(p.create_time())
        # Temporal filter: reject if this incarnation started after event_ts
        if event_ts is not None and create_time > event_ts:
            return None
        hostname = socket.gethostname()
        from agent.processor.entity_extractor import get_container_id
        ctr_id = get_container_id(pid)
        return {
            "id": f"{hostname}:{pid}:{create_time}",
            "name": name,
            "pid": pid,
            "cmd_line": cmd_line,
            "exe_path": exe_path,
            "hostname": hostname,
            "parent_pid": ppid,
            "bundle_id": "",
            "code_signed": None,
            "signing_authority": "",
            "container_id": ctr_id or "",
            "_fallback": "os",
            "_username": username,
            "_uid": uid,
        }
    except Exception:
        return None

# ── PID-index-aware query helpers ─────────────────────────────────────────


def _rows_for_pid(
    conn: kuzu.Connection,
    pid: int,
    id_query: str,
    pid_query: str,
    extra_params: dict | None = None,
) -> Generator[list, None, None]:
    """Yield result rows for all Process nodes matching *pid*.

    Uses the in-memory PID index for O(1) primary-key lookups when
    available.  Falls back to the original ``{pid: $pid}`` property scan
    (full table walk) when the index hasn't been built yet.

    *id_query* must use ``{id: $id}`` as the Process matcher.
    *pid_query* must use ``{pid: $pid}`` as the Process matcher.
    """
    index = get_pid_index()
    params = extra_params or {}

    if index.is_built:
        node_ids = index.get_node_ids(pid)
        for nid in node_ids:
            result = conn.execute(id_query, {"id": nid, **params})
            while result.has_next():
                yield result.get_next()
    else:
        result = conn.execute(pid_query, {"pid": pid, **params})
        while result.has_next():
            yield result.get_next()


def _query_process_fields(conn: kuzu.Connection, pid: int, event_ts: float | None = None) -> dict | None:
    """Fetch full fields for a process by PID.

    Uses the PID index for O(1) primary-key lookup when available.
    When *event_ts* is provided, selects the PID incarnation active at that
    time (largest create_time <= event_ts).  Falls back to newest-first
    iteration when event_ts is None (backward compat).
    Evicts stale pointers when an indexed node_id no longer exists in Kuzu.
    """
    _FIELDS = (
        "p.id, p.name, p.pid, p.cmd_line, p.exe_path, p.hostname, "
        "p.parent_pid, p.bundle_id, p.code_signed, p.signing_authority, p.start_time"
    )

    def _row_to_dict(row):
        return {
            "id": row[0],
            "name": row[1],
            "pid": row[2],
            "cmd_line": row[3],
            "exe_path": row[4],
            "hostname": row[5],
            "parent_pid": row[6],
            "bundle_id": row[7],
            "code_signed": row[8],
            "signing_authority": row[9],
            "start_time": row[10],
        }

    index = get_pid_index()
    if index.is_built:
        # Temporal lookup: single node_id when event_ts is provided
        if event_ts is not None:
            nid = index.get_node_id_at_time(pid, event_ts)
            if nid is not None:
                result = conn.execute(
                    f"MATCH (p:Process {{id: $id}}) RETURN {_FIELDS}",
                    {"id": nid},
                )
                if result.has_next():
                    return _row_to_dict(result.get_next())
                else:
                    index.remove_nodes([nid])
            # Fall through to ledger/OS fallback (handled by caller)
            return None

        # Non-temporal: iterate newest-first
        node_ids = index.get_node_ids(pid)
        stale: list[str] = []
        for nid in node_ids:
            result = conn.execute(
                f"MATCH (p:Process {{id: $id}}) RETURN {_FIELDS}",
                {"id": nid},
            )
            if result.has_next():
                if stale:
                    index.remove_nodes(stale)
                return _row_to_dict(result.get_next())
            else:
                stale.append(nid)
        if stale:
            index.remove_nodes(stale)
        return None
    else:
        # Fallback: full scan
        if event_ts is not None:
            result = conn.execute(
                f"MATCH (p:Process {{pid: $pid}}) RETURN {_FIELDS} "
                "ORDER BY p.start_time DESC LIMIT 1",
                {"pid": pid},
            )
        else:
            result = conn.execute(
                f"MATCH (p:Process {{pid: $pid}}) RETURN {_FIELDS}",
                {"pid": pid},
            )
        if result.has_next():
            return _row_to_dict(result.get_next())
        return None


def get_process_chain(conn: kuzu.Connection, pid: int, event_ts: float | None = None) -> list[dict]:
    """Walk parent_pid upward iteratively to build the full ancestor chain.

    Returns list from root ancestor down to the given PID (max 20 hops).
    Stops at PPID=1 (init/systemd) to avoid walking into system roots.
    Queries SPAWNED edges bottom-up to find the most relevant user.

    When *event_ts* is provided, all process lookups are temporally bounded
    to the PID incarnation active at that time.
    """
    try:
        current = _query_process_fields(conn, pid, event_ts)
        if current is None:
            current = _query_process_from_ledger(pid, event_ts)
        if current is None:
            current = _query_process_from_os(pid, event_ts)
        if current is None:
            return []

        chain = [current]
        visited = {pid}

        # Walk upward via parent_pid, with ledger + OS fallbacks.
        # Include PID 1 (init/systemd) when reached — it's a real ancestor —
        # but stop walking after it (its parent is PID 0 / kernel).
        for _ in range(20):
            ppid = current.get("parent_pid")
            if not ppid or ppid == 0 or ppid in visited:
                break
            visited.add(ppid)
            parent = _query_process_fields(conn, ppid, event_ts)
            if parent is None:
                parent = _query_process_from_ledger(ppid, event_ts)
            if parent is None:
                parent = _query_process_from_os(ppid, event_ts)
            if parent is None:
                break
            chain.insert(0, parent)
            current = parent

        # Query SPAWNED edges bottom-up (leaf -> root).
        # The deepest match is the most relevant user (e.g., "jsmith" on their
        # login shell, not "root" on sshd).
        found_user = False
        for proc_dict in reversed(chain):
            proc_id = proc_dict.get("id", "")
            if not proc_id:
                continue
            user_result = conn.execute(
                "MATCH (u:User)-[:SPAWNED]->(p:Process {id: $id}) RETURN u.id, u.name",
                {"id": proc_id},
            )
            if user_result.has_next():
                user_row = user_result.get_next()
                chain.insert(0, {"type": "user", "id": user_row[0], "name": user_row[1]})
                found_user = True
                break

        # Fallback: if no SPAWNED edge was found (common for daemons started
        # before the agent), check OS-fallback metadata on chain members, then
        # try psutil on the target PID as a last resort.
        if not found_user:
            for proc_dict in reversed(chain):
                uname = proc_dict.get("_username", "")
                if uname:
                    chain.insert(0, {"type": "user", "id": uname, "name": uname})
                    found_user = True
                    break
        if not found_user:
            import psutil
            # Walk bottom-up: the leaf PID may be dead (short-lived workers),
            # but a parent (or PID 1) will still be alive.
            for proc_dict in reversed(chain):
                try:
                    uname = psutil.Process(proc_dict.get("pid", 0)).username()
                    if uname:
                        chain.insert(0, {"type": "user", "id": uname, "name": uname})
                        break
                except Exception:
                    continue

        # Enrich process entries with container_id from /proc cgroup
        from agent.processor.entity_extractor import get_container_id
        for entry in chain:
            if entry.get("type") == "user":
                continue
            entry_pid = entry.get("pid", 0)
            if entry_pid and entry_pid > 0 and "container_id" not in entry:
                entry["container_id"] = get_container_id(entry_pid)

        return chain
    except Exception:
        logger.debug("Failed to get process chain for pid %d", pid, exc_info=True)
        return []


def graph_chain_to_chainsteps(graph_chain: list[dict]) -> list:
    """Convert get_process_chain() output dicts to ChainStep objects.

    get_process_chain() returns dicts like:
      - {"type": "user", "id": ..., "name": ...}
      - {"id": ..., "name": ..., "pid": ..., "parent_pid": ..., ...}
    """
    from agent.schema.graph_types import ChainStep

    steps = []
    for entry in graph_chain:
        if entry.get("type") == "user":
            steps.append(
                ChainStep(
                    entity_type="user",
                    entity_id=entry.get("id", ""),
                    entity_name=entry.get("name", ""),
                )
            )
        else:
            ctr_id = ""
            pid_val = entry.get("pid")
            if pid_val and pid_val > 0:
                from agent.processor.entity_extractor import get_container_id
                ctr_id = get_container_id(pid_val)
            steps.append(
                ChainStep(
                    entity_type="process",
                    entity_id=entry.get("id", ""),
                    entity_name=entry.get("name", ""),
                    pid=pid_val,
                    timestamp=entry.get("start_time"),
                    cmd_line=entry.get("cmd_line", ""),
                    container_id=ctr_id or None,
                )
            )
    return steps


def get_process_children(conn: kuzu.Connection, pid: int, limit: int = 50) -> list[dict]:
    """Get direct child processes via parent_pid.

    Uses the PID index ``ppid → child_pids`` mapping for O(1) lookup,
    then fetches each child by primary key.
    """
    _FIELDS = (
        "p.id, p.name, p.pid, p.cmd_line, p.exe_path, p.hostname, "
        "p.parent_pid, p.bundle_id, p.code_signed, p.signing_authority"
    )
    try:
        index = get_pid_index()
        if index.is_built:
            child_pids = index.get_children_pids(pid)[:limit]
            children = []
            stale: list[str] = []
            for cpid in child_pids:
                nid = index.get_latest_node_id(cpid)
                if nid is None:
                    continue
                result = conn.execute(
                    f"MATCH (p:Process {{id: $id}}) RETURN {_FIELDS}",
                    {"id": nid},
                )
                if result.has_next():
                    row = result.get_next()
                    children.append(
                        {
                            "id": row[0],
                            "name": row[1],
                            "pid": row[2],
                            "cmd_line": row[3],
                            "exe_path": row[4],
                            "hostname": row[5],
                            "parent_pid": row[6],
                            "bundle_id": row[7],
                            "code_signed": row[8],
                            "signing_authority": row[9],
                        }
                    )
                else:
                    stale.append(nid)
            if stale:
                index.remove_nodes(stale)
            return children

        # Fallback: full scan by parent_pid property
        result = conn.execute(
            f"MATCH (p:Process {{parent_pid: $pid}}) RETURN {_FIELDS} LIMIT $limit",
            {"pid": pid, "limit": limit},
        )
        children = []
        while result.has_next():
            row = result.get_next()
            children.append(
                {
                    "id": row[0],
                    "name": row[1],
                    "pid": row[2],
                    "cmd_line": row[3],
                    "exe_path": row[4],
                    "hostname": row[5],
                    "parent_pid": row[6],
                    "bundle_id": row[7],
                    "code_signed": row[8],
                    "signing_authority": row[9],
                }
            )
        return children
    except Exception:
        logger.debug("Failed to get children for pid %d", pid, exc_info=True)
        return []


def _get_pid_network(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Compact network info for all Process nodes sharing this PID."""
    items = []
    try:
        seen = set()
        for row in _rows_for_pid(
            conn,
            pid,
            "MATCH (p:Process {id: $id})-[c:CONNECTED_TO]->(ip:IP) RETURN ip.address, c.dst_port, c.protocol",
            "MATCH (p:Process {pid: $pid})-[c:CONNECTED_TO]->(ip:IP) RETURN ip.address, c.dst_port, c.protocol",
        ):
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                items.append({"address": row[0], "port": row[1], "protocol": row[2]})

        # DNS (direct)
        seen_domains: set[str] = set()
        for row in _rows_for_pid(
            conn,
            pid,
            "MATCH (p:Process {id: $id})-[:RESOLVED]->(d:Domain) RETURN d.name, d.is_dga_candidate",
            "MATCH (p:Process {pid: $pid})-[:RESOLVED]->(d:Domain) RETURN d.name, d.is_dga_candidate",
        ):
            if row[0] not in seen_domains:
                seen_domains.add(row[0])
                items.append({"domain": row[0], "is_dga": row[1]})

        # Infer domains from connected IPs (DNS goes to mDNSResponder, not the process)
        connected_ips = {i["address"] for i in items if "address" in i}
        for ip_addr in connected_ips:
            try:
                inferred = conn.execute(
                    "MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IP {address: $ip}) RETURN d.name, d.is_dga_candidate",
                    {"ip": ip_addr},
                )
                while inferred.has_next():
                    row = inferred.get_next()
                    if row[0] not in seen_domains:
                        seen_domains.add(row[0])
                        items.append({"domain": row[0], "is_dga": row[1]})
            except Exception:
                pass
    except Exception:
        pass
    return items


def _get_pid_files(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Compact file activity for all Process nodes sharing this PID."""
    items = []
    try:
        for rel_type, operation in [
            ("CREATED_FILE", "CREATED"),
            ("MODIFIED_FILE", "MODIFIED"),
            ("DELETED_FILE", "DELETED"),
            ("READ_FILE", "READ"),
        ]:
            for row in _rows_for_pid(
                conn,
                pid,
                f"MATCH (p:Process {{id: $id}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp ORDER BY r.timestamp DESC LIMIT 5",
                f"MATCH (p:Process {{pid: $pid}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp ORDER BY r.timestamp DESC LIMIT 5",
            ):
                items.append(
                    {
                        "file_path": row[0],
                        "operation": operation,
                        "timestamp": str(row[1]) if row[1] else None,
                    }
                )
    except Exception:
        pass
    return items


def get_process_tree(conn: kuzu.Connection, pid: int, event_ts: float | None = None) -> dict | None:
    """Build a full process tree: target + ancestors + descendants.

    BFS descendants (max depth 5). For each process, attaches network and file activity.
    When *event_ts* is provided, ancestor lookups are temporally bounded.
    """
    try:
        target = _query_process_fields(conn, pid, event_ts)
        if target is None:
            target = _query_process_from_ledger(pid, event_ts)
        if target is None:
            target = _query_process_from_os(pid, event_ts)
        if target is None:
            return None

        # Ancestors (with ledger + OS fallbacks for long-lived parents)
        ancestors = []
        visited = {pid}
        current = target
        for _ in range(20):
            ppid = current.get("parent_pid")
            if not ppid or ppid == 0 or ppid in visited:
                break
            visited.add(ppid)
            parent = _query_process_fields(conn, ppid, event_ts)
            if parent is None:
                parent = _query_process_from_ledger(ppid, event_ts)
            if parent is None:
                parent = _query_process_from_os(ppid, event_ts)
            if parent is None:
                break
            ancestors.insert(0, parent)
            current = parent

        # BFS descendants (capped to prevent fan-out explosion on PIDs like
        # kthreadd which parent thousands of kernel threads)
        _max_descendants = 100
        _descendant_count = 0

        def _build_subtree(root_pid: int, depth: int) -> list[dict]:
            nonlocal _descendant_count
            if depth <= 0 or _descendant_count >= _max_descendants:
                return []
            children = get_process_children(conn, root_pid, limit=25)
            many_children = len(children) > 10
            result = []
            for child in children:
                if _descendant_count >= _max_descendants:
                    break
                cpid = child["pid"]
                if cpid in visited:
                    continue
                visited.add(cpid)
                _descendant_count += 1
                # Skip expensive per-child enrichment when there are many
                # siblings (e.g. kthreadd's kernel threads have no
                # network/file activity anyway).
                if many_children:
                    child["network"] = []
                    child["files"] = []
                    child["children"] = []
                else:
                    child["network"] = _get_pid_network(conn, cpid)
                    child["files"] = _get_pid_files(conn, cpid)
                    child["children"] = _build_subtree(cpid, depth - 1)
                result.append(child)
            return result

        # Attach activity to target
        target["network"] = _get_pid_network(conn, pid)
        target["files"] = _get_pid_files(conn, pid)
        target["children"] = _build_subtree(pid, 5)

        # Attach activity to ancestors
        for anc in ancestors:
            anc["network"] = _get_pid_network(conn, anc["pid"])
            anc["files"] = _get_pid_files(conn, anc["pid"])

        return {
            "target": target,
            "ancestors": ancestors,
        }
    except Exception:
        logger.debug("Failed to build process tree for pid %d", pid, exc_info=True)
        return None


def get_process_network_footprint(conn: kuzu.Connection, pid: int) -> dict:
    """All network activity for a process.

    Queries by PID (not node ID) to catch all Process nodes sharing the same
    PID — activity events may create Process nodes with different IDs.

    Returns: {
        "domains": [{"name": ..., "first_seen": ..., "is_dga_candidate": ...}],
        "ips": [{"address": ..., "port": ..., "protocol": ...}],
        "dns_chains": [{"domain": ..., "resolved_to": [...]}]
    }
    """
    result = {
        "domains": [],
        "ips": [],
        "dns_chains": [],
        "listening_ports": [],
    }

    try:
        # Get direct IP connections
        seen_ips = set()
        for row in _rows_for_pid(
            conn,
            pid,
            "MATCH (p:Process {id: $id})-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, c.dst_port, c.protocol, "
            "ip.country, ip.classification, ip.provider_name",
            "MATCH (p:Process {pid: $pid})-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, c.dst_port, c.protocol, "
            "ip.country, ip.classification, ip.provider_name",
        ):
            key = (row[0], row[1])
            if key not in seen_ips:
                seen_ips.add(key)
                result["ips"].append(
                    {
                        "address": row[0],
                        "port": row[1],
                        "protocol": row[2],
                        "country": row[3] or "",
                        "classification": row[4] or "unclassified",
                        "provider_name": row[5] or "",
                    }
                )

        # Get direct DNS resolutions
        seen_domains: set[str] = set()
        for row in _rows_for_pid(
            conn,
            pid,
            "MATCH (p:Process {id: $id})-[:RESOLVED]->(d:Domain) RETURN d.name, d.first_seen, d.is_dga_candidate",
            "MATCH (p:Process {pid: $pid})-[:RESOLVED]->(d:Domain) RETURN d.name, d.first_seen, d.is_dga_candidate",
        ):
            if row[0] not in seen_domains:
                seen_domains.add(row[0])
                result["domains"].append(
                    {
                        "name": row[0],
                        "first_seen": str(row[1]) if row[1] else None,
                        "is_dga_candidate": row[2],
                    }
                )

        # Infer domains from IP connections: if Process->IP and Domain->IP,
        # the process likely queried that domain.
        connected_ips = {ip["address"] for ip in result["ips"]}
        if connected_ips:
            for ip_addr in connected_ips:
                try:
                    inferred = conn.execute(
                        "MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IP {address: $ip}) "
                        "RETURN d.name, d.first_seen, d.is_dga_candidate",
                        {"ip": ip_addr},
                    )
                    while inferred.has_next():
                        row = inferred.get_next()
                        if row[0] not in seen_domains:
                            seen_domains.add(row[0])
                            result["domains"].append(
                                {
                                    "name": row[0],
                                    "first_seen": str(row[1]) if row[1] else None,
                                    "is_dga_candidate": row[2],
                                    "inferred": True,
                                }
                            )
                except Exception:
                    pass

        # Get DNS chains (domain -> resolved IPs)
        for domain_name in seen_domains:
            chain_result = conn.execute(
                "MATCH (d:Domain {id: $domain})-[:RESOLVES_TO]->(ip:IP) RETURN ip.address",
                {"domain": domain_name},
            )
            resolved = []
            while chain_result.has_next():
                resolved.append(chain_result.get_next()[0])
            if resolved:
                result["dns_chains"].append(
                    {
                        "domain": domain_name,
                        "resolved_to": resolved,
                    }
                )

        # Get listening ports
        try:
            for row in _rows_for_pid(
                conn,
                pid,
                "MATCH (p:Process {id: $id})-[l:LISTENING_ON]->(ip:IP) RETURN ip.address, l.port, l.protocol",
                "MATCH (p:Process {pid: $pid})-[l:LISTENING_ON]->(ip:IP) RETURN ip.address, l.port, l.protocol",
            ):
                result["listening_ports"].append(
                    {
                        "address": row[0],
                        "port": row[1],
                        "protocol": row[2],
                    }
                )
        except Exception:
            pass  # LISTENING_ON table may not exist in older schemas

    except Exception:
        logger.debug("Failed to get network footprint for pid %d", pid, exc_info=True)

    return result


def get_domain_resolution_history(conn: kuzu.Connection, domain_name: str) -> list[dict]:
    """All IPs a domain has resolved to over time.

    Returns: [{"ip": ..., "first_seen": ..., "last_seen": ...}]
    """
    try:
        result = conn.execute(
            "MATCH (d:Domain {id: $domain})-[r:RESOLVES_TO]->(ip:IP) "
            "RETURN ip.address, ip.first_seen, ip.last_seen "
            "ORDER BY ip.first_seen",
            {"domain": domain_name.lower()},
        )
        history = []
        while result.has_next():
            row = result.get_next()
            history.append(
                {
                    "ip": row[0],
                    "first_seen": str(row[1]) if row[1] else None,
                    "last_seen": str(row[2]) if row[2] else None,
                }
            )
        return history
    except Exception:
        logger.debug("Failed to get resolution history for %s", domain_name, exc_info=True)
        return []


def get_file_activity(conn: kuzu.Connection, file_path: str) -> list[dict]:
    """All processes that touched a file and how.

    Returns: [{"pid": ..., "process_name": ..., "operation": "CREATED"|"MODIFIED"|"DELETED", "timestamp": ...}]
    """
    results = []
    try:
        for rel_type, operation in [
            ("CREATED_FILE", "CREATED"),
            ("MODIFIED_FILE", "MODIFIED"),
            ("DELETED_FILE", "DELETED"),
            ("READ_FILE", "READ"),
        ]:
            query_result = conn.execute(
                f"MATCH (p:Process)-[r:{rel_type}]->(f:File {{id: $path}}) "
                f"RETURN p.pid, p.name, r.timestamp "
                f"ORDER BY r.timestamp",
                {"path": file_path},
            )
            while query_result.has_next():
                row = query_result.get_next()
                results.append(
                    {
                        "pid": row[0],
                        "process_name": row[1],
                        "operation": operation,
                        "timestamp": str(row[2]) if row[2] else None,
                    }
                )
    except Exception:
        logger.debug("Failed to get file activity for %s", file_path, exc_info=True)

    return results


def get_persistence_artifacts(conn: kuzu.Connection, pid: int) -> list[dict]:
    """All registry persistence created by a process or its child tree.

    Walks the process tree downward and collects all RegistryKey nodes.
    Returns: [{"registry_path": ..., "value_name": ..., "value_data": ..., "created_by_pid": ...}]
    """
    artifacts = []
    try:
        for rel_type in ("CREATED_REG", "MODIFIED_REG"):
            for row in _rows_for_pid(
                conn,
                pid,
                f"MATCH (p:Process {{id: $id}})-[:{rel_type}]->(r:RegistryKey) "
                f"RETURN r.path, r.value_name, r.value_data, p.pid",
                f"MATCH (p:Process {{pid: $pid}})-[:{rel_type}]->(r:RegistryKey) "
                f"RETURN r.path, r.value_name, r.value_data, p.pid",
            ):
                artifacts.append(
                    {
                        "registry_path": row[0],
                        "value_name": row[1],
                        "value_data": row[2],
                        "created_by_pid": row[3],
                    }
                )
    except Exception:
        logger.debug("Failed to get persistence artifacts for pid %d", pid, exc_info=True)

    return artifacts


def build_attack_chain(conn: kuzu.Connection, pid: int) -> dict:
    """Comprehensive context object for LLM consumption.

    Uses get_process_tree() for full hierarchy. Returns target_process,
    process_chain (ancestors), child_processes, network_footprint,
    file_activity, persistence_artifacts, and risk_indicators.
    """
    t0 = time.monotonic()
    try:
        tree = get_process_tree(conn, pid)

        if tree is None:
            # No Process node in graph — still collect activity data for this PID
            # and try to identify the process via psutil
            target_info = {"pid": pid}
            try:
                import psutil

                p = psutil.Process(pid)
                target_info["name"] = p.name()
                with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
                    target_info["command_line"] = " ".join(p.cmdline())
                with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
                    target_info["parent_pid"] = p.ppid()
            except Exception:
                pass

            network_footprint = get_process_network_footprint(conn, pid)
            file_activity = _get_process_file_activity(conn, pid)

            chain = {
                "target_process": target_info,
                "process_chain": [],
                "child_processes": [],
                "network_footprint": network_footprint,
                "file_activity": file_activity,
                "persistence_artifacts": get_persistence_artifacts(conn, pid),
                "risk_indicators": [],
            }

            for domain in network_footprint.get("domains", []):
                if domain.get("is_dga_candidate"):
                    chain["risk_indicators"].append(f"DGA candidate: {domain['name']}")

            elapsed = time.monotonic() - t0
            metrics.attack_chain_build_latency.observe(elapsed)
            return chain

        target = tree["target"]

        # Build target_process dict
        target_info = {
            "pid": target["pid"],
            "name": target["name"],
            "command_line": target.get("cmd_line"),
            "hostname": target.get("hostname"),
            "parent_pid": target.get("parent_pid"),
            "bundle_id": target.get("bundle_id"),
            "code_signed": target.get("code_signed"),
            "signing_authority": target.get("signing_authority"),
        }

        # Try to get the user — walk bottom-up (target first, then ancestors toward root)
        # so the effective user of the executing process wins over system daemons (e.g. launchd/root).
        ancestors = tree.get("ancestors", [])
        candidate_ids = [target["id"]] + [a["id"] for a in reversed(ancestors)]
        for cid in candidate_ids:
            user_result = conn.execute(
                "MATCH (u:User)-[:SPAWNED]->(p:Process {id: $id}) RETURN u.name",
                {"id": cid},
            )
            if user_result.has_next():
                target_info["user"] = user_result.get_next()[0]
                break

        # Build process_chain (ancestors + target, each with cmd_line)
        # Prepend user as first chain entry if found
        process_chain = []
        if target_info.get("user"):
            process_chain.append({"type": "user", "name": target_info["user"]})
        from agent.processor.entity_extractor import get_container_id

        for anc in ancestors:
            anc_pid = anc["pid"]
            process_chain.append(
                {
                    "name": anc["name"],
                    "pid": anc_pid,
                    "cmd_line": anc.get("cmd_line"),
                    "parent_pid": anc.get("parent_pid"),
                    "code_signed": anc.get("code_signed"),
                    "signing_authority": anc.get("signing_authority"),
                    "container_id": get_container_id(anc_pid) if anc_pid and anc_pid > 0 else "",
                }
            )
        target_pid = target["pid"]
        process_chain.append(
            {
                "name": target["name"],
                "pid": target_pid,
                "cmd_line": target.get("cmd_line"),
                "parent_pid": target.get("parent_pid"),
                "code_signed": target.get("code_signed"),
                "signing_authority": target.get("signing_authority"),
                "container_id": get_container_id(target_pid) if target_pid and target_pid > 0 else "",
            }
        )

        # Build child_processes recursively
        def _serialize_children(children: list[dict]) -> list[dict]:
            result = []
            for child in children:
                result.append(
                    {
                        "pid": child["pid"],
                        "name": child["name"],
                        "cmd_line": child.get("cmd_line"),
                        "code_signed": child.get("code_signed"),
                        "signing_authority": child.get("signing_authority"),
                        "network": child.get("network", []),
                        "files": child.get("files", []),
                        "children": _serialize_children(child.get("children", [])),
                    }
                )
            return result

        child_processes = _serialize_children(target.get("children", []))

        # Network footprint from target process
        network_footprint = get_process_network_footprint(conn, pid)

        # File activity from target
        file_activity = _get_process_file_activity(conn, pid)

        chain = {
            "target_process": target_info,
            "process_chain": process_chain,
            "child_processes": child_processes,
            "network_footprint": network_footprint,
            "file_activity": file_activity,
            "persistence_artifacts": get_persistence_artifacts(conn, pid),
            "risk_indicators": [],
        }

        # Populate risk indicators from DGA detections
        for domain in chain["network_footprint"].get("domains", []):
            if domain.get("is_dga_candidate"):
                chain["risk_indicators"].append(f"DGA candidate: {domain['name']}")

        # Populate risk indicators from persistence artifacts
        for artifact in chain["persistence_artifacts"]:
            chain["risk_indicators"].append(
                f"Persistence: {artifact.get('registry_path', 'unknown')} (value: {artifact.get('value_data', 'N/A')})"
            )

        elapsed = time.monotonic() - t0
        metrics.attack_chain_build_latency.observe(elapsed)
        return chain
    except Exception:
        logger.debug("Failed to build attack chain for pid %d", pid, exc_info=True)
        elapsed = time.monotonic() - t0
        metrics.attack_chain_build_latency.observe(elapsed)
        return {
            "target_process": {},
            "process_chain": [],
            "child_processes": [],
            "network_footprint": {"domains": [], "ips": [], "dns_chains": []},
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
        }


def _get_process_file_activity(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Get file activity for a specific process (by pid).

    Returns top 10 most recent file operations.
    """
    results = []
    try:
        for rel_type, operation in [
            ("CREATED_FILE", "CREATED"),
            ("MODIFIED_FILE", "MODIFIED"),
            ("DELETED_FILE", "DELETED"),
            ("READ_FILE", "READ"),
        ]:
            for row in _rows_for_pid(
                conn,
                pid,
                f"MATCH (p:Process {{id: $id}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp ORDER BY r.timestamp DESC LIMIT 10",
                f"MATCH (p:Process {{pid: $pid}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp ORDER BY r.timestamp DESC LIMIT 10",
            ):
                results.append(
                    {
                        "file_path": row[0],
                        "operation": operation,
                        "timestamp": str(row[1]) if row[1] else None,
                    }
                )
    except Exception:
        logger.debug("Failed to get file activity for pid %d", pid, exc_info=True)

    # Sort by timestamp, take top 10
    results.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return results[:10]


def _format_signing(proc: dict) -> str:
    """Format signing info for a process dict."""
    if proc.get("code_signed"):
        signer = proc.get("signing_authority", "unknown")
        return f"[signed={signer}]"
    elif proc.get("code_signed") is False:
        return "[unsigned]"
    return ""


def _serialize_tree_node(proc: dict, indent: int, parts: list[str]) -> None:
    """Recursively render a process tree node with its activity."""
    prefix = "  " * indent
    sign = _format_signing(proc)
    cmd = f' cmd="{proc.get("cmd_line", "")}"' if proc.get("cmd_line") else ""
    parts.append(f"{prefix}{proc.get('name', '?')} (PID {proc.get('pid', '?')}){cmd} {sign}".rstrip())

    # Network bullets
    for item in proc.get("network", []):
        if "domain" in item:
            dga = " [DGA?]" if item.get("is_dga") else ""
            parts.append(f"{prefix}  DNS: {item['domain']}{dga}")
        elif "address" in item:
            parts.append(
                f"{prefix}  Network: -> {item['address']}:{item.get('port', '?')} ({item.get('protocol', 'TCP')})"
            )

    # File bullets
    for item in proc.get("files", []):
        parts.append(f"{prefix}  File: {item.get('operation', '?')} {item.get('file_path', '?')}")

    # Recurse children
    for child in proc.get("children", []):
        _serialize_tree_node(child, indent + 1, parts)


def serialize_attack_chain(chain: dict, max_tokens: int = 2000) -> str:
    """Serialize attack chain to a concise string for LLM context.

    Renders the process tree hierarchically. Each process shows:
    name (PID) cmd="..." [signed/unsigned]
    Indented children. Each process followed by network/file/DNS bullets.
    """
    max_chars = max_tokens * 4  # rough token estimate

    parts = []

    # Target process header
    target = chain.get("target_process", {})
    if target:
        target_line = (
            f"Target: {target.get('name', '?')} (PID {target.get('pid', '?')}) "
            f"cmd={target.get('command_line', 'N/A')} "
            f"user={target.get('user', 'N/A')}"
        )
        if target.get("bundle_id"):
            target_line += f" bundle={target['bundle_id']}"
        sign = _format_signing(target)
        if sign:
            target_line += f" {sign}"
        parts.append(target_line)

    # Process chain (ancestors) — rendered as tree
    pchain = chain.get("process_chain", [])
    if pchain:
        parts.append("Process tree:")
        for i, p in enumerate(pchain):
            indent = i
            sign = _format_signing(p)
            cmd = f' cmd="{p.get("cmd_line", "")}"' if p.get("cmd_line") else ""
            parts.append(f"{'  ' * indent}{p.get('name', '?')} (PID {p.get('pid', '?')}){cmd} {sign}".rstrip())

    # Child processes — rendered as tree continuation
    children = chain.get("child_processes", [])
    if children:
        base_indent = len(pchain) if pchain else 1
        for child in children:
            _serialize_tree_node(child, base_indent, parts)

    # Network footprint
    net = chain.get("network_footprint", {})
    domains = net.get("domains", [])
    if domains:
        domain_strs = []
        for d in domains[:5]:
            s = d.get("name", "?")
            if d.get("is_dga_candidate"):
                s += " [DGA?]"
            domain_strs.append(s)
        parts.append(f"DNS queries: {', '.join(domain_strs)}")

    ips = net.get("ips", [])
    if ips:
        ip_strs = []
        for i in ips[:5]:
            s = f"{i.get('address', '?')}:{i.get('port', '?')}"
            cls = i.get("classification", "")
            prov = i.get("provider_name", "")
            if cls and cls != "unclassified":
                s += f" [{cls}]"
                if prov:
                    s += f" ({prov})"
            ip_strs.append(s)
        parts.append(f"Connections: {', '.join(ip_strs)}")

    listening = net.get("listening_ports", [])
    if listening:
        listen_strs = [
            f"{ep.get('address', '?')}:{ep.get('port', '?')}/{ep.get('protocol', '?')}" for ep in listening[:5]
        ]
        parts.append(f"Listening on: {', '.join(listen_strs)}")

    # Connection context (enrichment data)
    conn_ctx = chain.get("connection_context", [])
    if conn_ctx:
        parts.append("Connection context:")
        for ctx in conn_ctx[:5]:
            parts.append(f"  {ctx}")

    dns_chains = net.get("dns_chains", [])
    if dns_chains:
        for dc in dns_chains[:3]:
            resolved = ", ".join(dc.get("resolved_to", [])[:3])
            parts.append(f"  {dc.get('domain', '?')} -> [{resolved}]")

    # File activity
    files = chain.get("file_activity", [])
    if files:
        file_strs = [f"{f.get('operation', '?')} {f.get('file_path', '?')}" for f in files[:10]]
        parts.append(f"File ops: {'; '.join(file_strs)}")

    # Persistence
    persist = chain.get("persistence_artifacts", [])
    if persist:
        persist_strs = [f"{p.get('registry_path', '?')}={p.get('value_data', '?')}" for p in persist[:5]]
        parts.append(f"Persistence: {'; '.join(persist_strs)}")

    # Risk indicators
    risks = chain.get("risk_indicators", [])
    if risks:
        parts.append(f"Risk indicators: {'; '.join(str(r) for r in risks[:10])}")

    text = "\n".join(parts)

    # Truncate if too long
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "\n... (truncated)"

    return text


def get_ioc_summary(conn: kuzu.Connection, limit: int = 50) -> dict:
    """Global IOC/IOA summary from the graph.

    Returns all domains, external IPs, and recently modified files with
    the processes that touched them. Useful because many events (FSEvents,
    DNS) are attributed to system processes (PID 0 / mDNSResponder) rather
    than the actual initiating process.
    """
    result = {
        "domains": [],
        "external_ips": [],
        "files": [],
    }

    # Domains
    try:
        dns = conn.execute(
            "MATCH (p:Process)-[:RESOLVED]->(d:Domain) "
            "RETURN d.name, d.is_dga_candidate, d.first_seen, "
            "collect(DISTINCT p.name), collect(DISTINCT p.pid) "
            "ORDER BY d.first_seen DESC LIMIT $limit",
            {"limit": limit},
        )
        while dns.has_next():
            row = dns.get_next()
            domain_name = row[0]
            # Get IPs this domain resolves to (for transitive finding linking)
            resolved_ips = []
            try:
                ip_result = conn.execute(
                    "MATCH (d:Domain {name: $name})-[:RESOLVES_TO]->(ip:IP) RETURN ip.address",
                    {"name": domain_name},
                )
                while ip_result.has_next():
                    resolved_ips.append(ip_result.get_next()[0])
            except Exception:
                pass
            result["domains"].append(
                {
                    "name": domain_name,
                    "is_dga_candidate": row[1],
                    "first_seen": str(row[2]) if row[2] else None,
                    "resolved_by": row[3],
                    "resolved_by_pids": row[4],
                    "resolved_ips": resolved_ips,
                }
            )
    except Exception:
        logger.debug("IOC domain query failed", exc_info=True)

    # IPs
    try:
        ips = conn.execute(
            "MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, ip.is_private, collect(DISTINCT c.dst_port), "
            "collect(DISTINCT p.name), collect(DISTINCT p.pid), "
            "min(ip.first_seen) AS fs, "
            "ip.country, ip.isp, ip.classification, ip.provider_name, ip.reverse_dns "
            "ORDER BY fs DESC LIMIT $limit",
            {"limit": limit},
        )
        while ips.has_next():
            row = ips.get_next()
            is_private = row[1]
            if is_private is True:
                continue
            result["external_ips"].append(
                {
                    "address": row[0],
                    "ports": row[2],
                    "connected_by": row[3],
                    "connected_by_pids": row[4],
                    "country": row[6] or "",
                    "isp": row[7] or "",
                    "classification": row[8] or "unclassified",
                    "provider_name": row[9] or "",
                    "reverse_dns": row[10] or "",
                }
            )
    except Exception:
        logger.debug("IOC IP query failed", exc_info=True)

    # Files — aggregate all processes per file, filter out PID 0 / "unknown"
    for rel_type, operation in [
        ("CREATED_FILE", "CREATED"),
        ("MODIFIED_FILE", "MODIFIED"),
        ("DELETED_FILE", "DELETED"),
    ]:
        try:
            files = conn.execute(
                f"MATCH (p:Process)-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, p.name, p.pid, r.timestamp "
                f"ORDER BY r.timestamp DESC LIMIT $limit",
                {"limit": limit // 3},
            )
            seen_paths = set()
            while files.has_next():
                row = files.get_next()
                path = row[0]
                proc_name = row[1]
                proc_pid = row[2]
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                # Filter out PID 0 / "unknown" process
                by_procs = []
                by_pids = []
                if proc_pid and proc_pid > 0:
                    by_procs = [proc_name] if proc_name else []
                    by_pids = [proc_pid]
                result["files"].append(
                    {
                        "path": path,
                        "operation": operation,
                        "by_processes": by_procs,
                        "by_pids": by_pids,
                        "timestamp": str(row[3]) if row[3] else None,
                    }
                )
        except Exception:
            logger.debug("IOC file query failed for %s", rel_type, exc_info=True)

    return result
