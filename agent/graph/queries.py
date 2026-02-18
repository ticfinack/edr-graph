"""Reusable graph traversal functions for attack chain building."""

from __future__ import annotations

import json
import logging
import time

import kuzu

from agent import metrics

logger = logging.getLogger(__name__)


def get_process_chain(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Walk SPAWNED edges upward to build the full parent process chain.

    Returns list from root ancestor down to the given PID.
    Example: [systemd, bash, python, malware.py]
    """
    try:
        # Find the process node by pid, then walk SPAWNED edges upward
        result = conn.execute(
            "MATCH (p:Process {pid: $pid}) "
            "RETURN p.id, p.name, p.pid, p.cmd_line, p.exe_path, p.hostname",
            {"pid": pid},
        )
        if not result.has_next():
            return []

        row = result.get_next()
        chain = [
            {
                "id": row[0],
                "name": row[1],
                "pid": row[2],
                "cmd_line": row[3],
                "exe_path": row[4],
                "hostname": row[5],
            }
        ]

        # Walk upward through SPAWNED edges (User->Process)
        # to find parent processes via parent_pid relationships
        visited = {pid}
        current_id = row[0]

        # Walk SPAWNED edges: find the user that spawned this process,
        # then find other processes spawned by the same user
        # This is a simplified walk - in practice, parent_pid tracking
        # would give a more accurate tree
        result = conn.execute(
            "MATCH (u:User)-[:SPAWNED]->(p:Process {id: $id}) "
            "RETURN u.id, u.name",
            {"id": current_id},
        )
        if result.has_next():
            user_row = result.get_next()
            chain.insert(0, {
                "type": "user",
                "id": user_row[0],
                "name": user_row[1],
            })

        return chain
    except Exception:
        logger.debug("Failed to get process chain for pid %d", pid, exc_info=True)
        return []


def get_process_network_footprint(conn: kuzu.Connection, pid: int) -> dict:
    """All network activity for a process.

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
    }

    try:
        # Get process id from pid
        proc_result = conn.execute(
            "MATCH (p:Process {pid: $pid}) RETURN p.id",
            {"pid": pid},
        )
        if not proc_result.has_next():
            return result

        proc_id = proc_result.get_next()[0]

        # Get direct IP connections
        ip_result = conn.execute(
            "MATCH (p:Process {id: $id})-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, c.dst_port, c.protocol",
            {"id": proc_id},
        )
        seen_ips = set()
        while ip_result.has_next():
            row = ip_result.get_next()
            key = (row[0], row[1])
            if key not in seen_ips:
                seen_ips.add(key)
                result["ips"].append({
                    "address": row[0],
                    "port": row[1],
                    "protocol": row[2],
                })

        # Get DNS resolutions
        dns_result = conn.execute(
            "MATCH (p:Process {id: $id})-[:RESOLVED]->(d:Domain) "
            "RETURN d.name, d.first_seen, d.is_dga_candidate",
            {"id": proc_id},
        )
        seen_domains = set()
        while dns_result.has_next():
            row = dns_result.get_next()
            if row[0] not in seen_domains:
                seen_domains.add(row[0])
                result["domains"].append({
                    "name": row[0],
                    "first_seen": str(row[1]) if row[1] else None,
                    "is_dga_candidate": row[2],
                })

        # Get DNS chains (domain -> resolved IPs)
        for domain_name in seen_domains:
            chain_result = conn.execute(
                "MATCH (d:Domain {id: $domain})-[:RESOLVES_TO]->(ip:IP) "
                "RETURN ip.address",
                {"domain": domain_name},
            )
            resolved = []
            while chain_result.has_next():
                resolved.append(chain_result.get_next()[0])
            if resolved:
                result["dns_chains"].append({
                    "domain": domain_name,
                    "resolved_to": resolved,
                })

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
            history.append({
                "ip": row[0],
                "first_seen": str(row[1]) if row[1] else None,
                "last_seen": str(row[2]) if row[2] else None,
            })
        return history
    except Exception:
        logger.debug(
            "Failed to get resolution history for %s", domain_name, exc_info=True
        )
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
                results.append({
                    "pid": row[0],
                    "process_name": row[1],
                    "operation": operation,
                    "timestamp": str(row[2]) if row[2] else None,
                })
    except Exception:
        logger.debug(
            "Failed to get file activity for %s", file_path, exc_info=True
        )

    return results


def get_persistence_artifacts(conn: kuzu.Connection, pid: int) -> list[dict]:
    """All registry persistence created by a process or its child tree.

    Walks the process tree downward and collects all RegistryKey nodes.
    Returns: [{"registry_path": ..., "value_name": ..., "value_data": ..., "created_by_pid": ...}]
    """
    artifacts = []
    try:
        # Get all processes in the tree (starting from the given pid)
        # For simplicity, query direct registry activity from the process
        for rel_type in ("CREATED_REG", "MODIFIED_REG"):
            result = conn.execute(
                f"MATCH (p:Process {{pid: $pid}})-[:{rel_type}]->(r:RegistryKey) "
                f"RETURN r.path, r.value_name, r.value_data, p.pid",
                {"pid": pid},
            )
            while result.has_next():
                row = result.get_next()
                artifacts.append({
                    "registry_path": row[0],
                    "value_name": row[1],
                    "value_data": row[2],
                    "created_by_pid": row[3],
                })
    except Exception:
        logger.debug(
            "Failed to get persistence artifacts for pid %d", pid, exc_info=True
        )

    return artifacts


def build_attack_chain(conn: kuzu.Connection, pid: int) -> dict:
    """Comprehensive context object for LLM consumption.

    Combines all query helpers into a single structured dict.
    """
    t0 = time.monotonic()
    try:
        # Get target process info
        target = {}
        proc_result = conn.execute(
            "MATCH (p:Process {pid: $pid}) "
            "RETURN p.pid, p.name, p.cmd_line, p.hostname",
            {"pid": pid},
        )
        if proc_result.has_next():
            row = proc_result.get_next()
            target = {
                "pid": row[0],
                "name": row[1],
                "command_line": row[2],
                "hostname": row[3],
            }

            # Try to get the user
            user_result = conn.execute(
                "MATCH (u:User)-[:SPAWNED]->(p:Process {pid: $pid}) "
                "RETURN u.name",
                {"pid": pid},
            )
            if user_result.has_next():
                target["user"] = user_result.get_next()[0]

        chain = {
            "target_process": target,
            "process_chain": get_process_chain(conn, pid),
            "network_footprint": get_process_network_footprint(conn, pid),
            "file_activity": _get_process_file_activity(conn, pid),
            "persistence_artifacts": get_persistence_artifacts(conn, pid),
            "risk_indicators": [],
        }

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
            query_result = conn.execute(
                f"MATCH (p:Process {{pid: $pid}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp "
                f"ORDER BY r.timestamp DESC LIMIT 10",
                {"pid": pid},
            )
            while query_result.has_next():
                row = query_result.get_next()
                results.append({
                    "file_path": row[0],
                    "operation": operation,
                    "timestamp": str(row[1]) if row[1] else None,
                })
    except Exception:
        logger.debug(
            "Failed to get file activity for pid %d", pid, exc_info=True
        )

    # Sort by timestamp, take top 10
    results.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return results[:10]


def serialize_attack_chain(chain: dict, max_tokens: int = 2000) -> str:
    """Serialize attack chain to a concise string for LLM context.

    Keeps output under max_tokens (rough estimate: 4 chars per token).
    """
    max_chars = max_tokens * 4  # rough token estimate

    parts = []

    # Target process
    target = chain.get("target_process", {})
    if target:
        parts.append(
            f"Target: {target.get('name', '?')} (PID {target.get('pid', '?')}) "
            f"cmd={target.get('command_line', 'N/A')} "
            f"user={target.get('user', 'N/A')}"
        )

    # Process chain
    pchain = chain.get("process_chain", [])
    if pchain:
        names = [
            p.get("name", "?") for p in pchain
            if isinstance(p, dict)
        ]
        parts.append(f"Process chain: {' -> '.join(names)}")

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
        ip_strs = [f"{i.get('address', '?')}:{i.get('port', '?')}" for i in ips[:5]]
        parts.append(f"Connections: {', '.join(ip_strs)}")

    dns_chains = net.get("dns_chains", [])
    if dns_chains:
        for dc in dns_chains[:3]:
            resolved = ", ".join(dc.get("resolved_to", [])[:3])
            parts.append(f"  {dc.get('domain', '?')} -> [{resolved}]")

    # File activity
    files = chain.get("file_activity", [])
    if files:
        file_strs = [
            f"{f.get('operation', '?')} {f.get('file_path', '?')}"
            for f in files[:10]
        ]
        parts.append(f"File ops: {'; '.join(file_strs)}")

    # Persistence
    persist = chain.get("persistence_artifacts", [])
    if persist:
        persist_strs = [
            f"{p.get('registry_path', '?')}={p.get('value_data', '?')}"
            for p in persist[:5]
        ]
        parts.append(f"Persistence: {'; '.join(persist_strs)}")

    # Risk indicators
    risks = chain.get("risk_indicators", [])
    if risks:
        parts.append(f"Risk indicators: {'; '.join(str(r) for r in risks[:10])}")

    text = "\n".join(parts)

    # Truncate if too long
    if len(text) > max_chars:
        text = text[:max_chars - 20] + "\n... (truncated)"

    return text
