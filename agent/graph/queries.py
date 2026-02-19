"""Reusable graph traversal functions for attack chain building."""

from __future__ import annotations

import logging
import time

import kuzu

from agent import metrics

logger = logging.getLogger(__name__)


def _query_process_fields(conn: kuzu.Connection, pid: int) -> dict | None:
    """Fetch full fields for a process by PID."""
    result = conn.execute(
        "MATCH (p:Process {pid: $pid}) "
        "RETURN p.id, p.name, p.pid, p.cmd_line, p.exe_path, p.hostname, "
        "p.parent_pid, p.bundle_id, p.code_signed, p.signing_authority",
        {"pid": pid},
    )
    if not result.has_next():
        return None
    row = result.get_next()
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
    }


def get_process_chain(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Walk parent_pid upward iteratively to build the full ancestor chain.

    Returns list from root ancestor down to the given PID (max 20 hops).
    Prepends User from SPAWNED edge if found on the root process.
    """
    try:
        current = _query_process_fields(conn, pid)
        if current is None:
            return []

        chain = [current]
        visited = {pid}

        # Walk upward via parent_pid
        for _ in range(20):
            ppid = current.get("parent_pid")
            if not ppid or ppid == 0 or ppid in visited:
                break
            visited.add(ppid)
            parent = _query_process_fields(conn, ppid)
            if parent is None:
                break
            chain.insert(0, parent)
            current = parent

        # Prepend User from SPAWNED edge on the root process
        root_id = chain[0].get("id", "")
        if root_id:
            user_result = conn.execute(
                "MATCH (u:User)-[:SPAWNED]->(p:Process {id: $id}) "
                "RETURN u.id, u.name",
                {"id": root_id},
            )
            if user_result.has_next():
                user_row = user_result.get_next()
                chain.insert(0, {
                    "type": "user",
                    "id": user_row[0],
                    "name": user_row[1],
                })

        return chain
    except Exception:
        logger.debug("Failed to get process chain for pid %d", pid, exc_info=True)
        return []


def get_process_children(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Get direct child processes via parent_pid."""
    try:
        result = conn.execute(
            "MATCH (p:Process {parent_pid: $pid}) "
            "RETURN p.id, p.name, p.pid, p.cmd_line, p.exe_path, p.hostname, "
            "p.parent_pid, p.bundle_id, p.code_signed, p.signing_authority",
            {"pid": pid},
        )
        children = []
        while result.has_next():
            row = result.get_next()
            children.append({
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
            })
        return children
    except Exception:
        logger.debug("Failed to get children for pid %d", pid, exc_info=True)
        return []


def _get_pid_network(conn: kuzu.Connection, pid: int) -> list[dict]:
    """Compact network info for all Process nodes sharing this PID.

    Activity events (network, DNS) may create Process nodes with different
    IDs than the original process event (missing created_time leads to a
    different timestamp component).  Querying by PID catches all of them.
    """
    items = []
    try:
        result = conn.execute(
            "MATCH (p:Process {pid: $pid})-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, c.dst_port, c.protocol",
            {"pid": pid},
        )
        seen = set()
        while result.has_next():
            row = result.get_next()
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                items.append({"address": row[0], "port": row[1], "protocol": row[2]})

        # DNS (direct)
        dns_result = conn.execute(
            "MATCH (p:Process {pid: $pid})-[:RESOLVED]->(d:Domain) "
            "RETURN d.name, d.is_dga_candidate",
            {"pid": pid},
        )
        seen_domains = set()
        while dns_result.has_next():
            row = dns_result.get_next()
            if row[0] not in seen_domains:
                seen_domains.add(row[0])
                items.append({"domain": row[0], "is_dga": row[1]})

        # Infer domains from connected IPs (DNS goes to mDNSResponder, not the process)
        connected_ips = {i["address"] for i in items if "address" in i}
        for ip_addr in connected_ips:
            try:
                inferred = conn.execute(
                    "MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IP {address: $ip}) "
                    "RETURN d.name, d.is_dga_candidate",
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
            result = conn.execute(
                f"MATCH (p:Process {{pid: $pid}})-[r:{rel_type}]->(f:File) "
                f"RETURN f.path, r.timestamp ORDER BY r.timestamp DESC LIMIT 5",
                {"pid": pid},
            )
            while result.has_next():
                row = result.get_next()
                items.append({
                    "file_path": row[0],
                    "operation": operation,
                    "timestamp": str(row[1]) if row[1] else None,
                })
    except Exception:
        pass
    return items


def get_process_tree(conn: kuzu.Connection, pid: int) -> dict | None:
    """Build a full process tree: target + ancestors + descendants.

    BFS descendants (max depth 5). For each process, attaches network and file activity.
    """
    try:
        target = _query_process_fields(conn, pid)
        if target is None:
            return None

        # Ancestors
        ancestors = []
        visited = {pid}
        current = target
        for _ in range(20):
            ppid = current.get("parent_pid")
            if not ppid or ppid == 0 or ppid in visited:
                break
            visited.add(ppid)
            parent = _query_process_fields(conn, ppid)
            if parent is None:
                break
            ancestors.insert(0, parent)
            current = parent

        # BFS descendants
        def _build_subtree(root_pid: int, depth: int) -> list[dict]:
            if depth <= 0:
                return []
            children = get_process_children(conn, root_pid)
            result = []
            for child in children:
                cpid = child["pid"]
                if cpid in visited:
                    continue
                visited.add(cpid)
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
        # Get direct IP connections (by PID to catch all node variants)
        ip_result = conn.execute(
            "MATCH (p:Process {pid: $pid})-[c:CONNECTED_TO]->(ip:IP) "
            "RETURN ip.address, c.dst_port, c.protocol, "
            "ip.country, ip.classification, ip.provider_name",
            {"pid": pid},
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
                    "country": row[3] or "",
                    "classification": row[4] or "unclassified",
                    "provider_name": row[5] or "",
                })

        # Get direct DNS resolutions (by PID)
        dns_result = conn.execute(
            "MATCH (p:Process {pid: $pid})-[:RESOLVED]->(d:Domain) "
            "RETURN d.name, d.first_seen, d.is_dga_candidate",
            {"pid": pid},
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

        # Infer domains from IP connections: if Process→IP and Domain→IP,
        # the process likely queried that domain.  DNS events go to
        # mDNSResponder (PID 0), so direct RESOLVED edges are usually
        # missing for the actual initiating process.
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
                            result["domains"].append({
                                "name": row[0],
                                "first_seen": str(row[1]) if row[1] else None,
                                "is_dga_candidate": row[2],
                                "inferred": True,
                            })
                except Exception:
                    pass

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

        # Get listening ports (by PID)
        try:
            listen_result = conn.execute(
                "MATCH (p:Process {pid: $pid})-[l:LISTENING_ON]->(ip:IP) "
                "RETURN ip.address, l.port, l.protocol",
                {"pid": pid},
            )
            while listen_result.has_next():
                row = listen_result.get_next()
                result["listening_ports"].append({
                    "address": row[0],
                    "port": row[1],
                    "protocol": row[2],
                })
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
                try:
                    target_info["command_line"] = " ".join(p.cmdline())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    target_info["parent_pid"] = p.ppid()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
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
                    chain["risk_indicators"].append(
                        f"DGA candidate: {domain['name']}"
                    )

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

        # Try to get the user (from SPAWNED edge on root ancestor or target)
        ancestors = tree.get("ancestors", [])
        root_id = ancestors[0]["id"] if ancestors else target["id"]
        user_result = conn.execute(
            "MATCH (u:User)-[:SPAWNED]->(p:Process {id: $id}) "
            "RETURN u.name",
            {"id": root_id},
        )
        if user_result.has_next():
            target_info["user"] = user_result.get_next()[0]

        # Build process_chain (ancestors + target, each with cmd_line)
        process_chain = []
        for anc in ancestors:
            process_chain.append({
                "name": anc["name"],
                "pid": anc["pid"],
                "cmd_line": anc.get("cmd_line"),
                "parent_pid": anc.get("parent_pid"),
                "code_signed": anc.get("code_signed"),
                "signing_authority": anc.get("signing_authority"),
            })
        process_chain.append({
            "name": target["name"],
            "pid": target["pid"],
            "cmd_line": target.get("cmd_line"),
            "parent_pid": target.get("parent_pid"),
            "code_signed": target.get("code_signed"),
            "signing_authority": target.get("signing_authority"),
        })

        # Build child_processes recursively
        def _serialize_children(children: list[dict]) -> list[dict]:
            result = []
            for child in children:
                result.append({
                    "pid": child["pid"],
                    "name": child["name"],
                    "cmd_line": child.get("cmd_line"),
                    "code_signed": child.get("code_signed"),
                    "signing_authority": child.get("signing_authority"),
                    "network": child.get("network", []),
                    "files": child.get("files", []),
                    "children": _serialize_children(child.get("children", [])),
                })
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
                chain["risk_indicators"].append(
                    f"DGA candidate: {domain['name']}"
                )

        # Populate risk indicators from persistence artifacts
        for artifact in chain["persistence_artifacts"]:
            chain["risk_indicators"].append(
                f"Persistence: {artifact.get('registry_path', 'unknown')} "
                f"(value: {artifact.get('value_data', 'N/A')})"
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
    parts.append(
        f"{prefix}{proc.get('name', '?')} (PID {proc.get('pid', '?')}){cmd} {sign}".rstrip()
    )

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
            parts.append(
                f"{'  ' * indent}{p.get('name', '?')} (PID {p.get('pid', '?')}){cmd} {sign}".rstrip()
            )

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
            f"{ep.get('address', '?')}:{ep.get('port', '?')}/{ep.get('protocol', '?')}"
            for ep in listening[:5]
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
                    "MATCH (d:Domain {name: $name})-[:RESOLVES_TO]->(ip:IP) "
                    "RETURN ip.address",
                    {"name": domain_name},
                )
                while ip_result.has_next():
                    resolved_ips.append(ip_result.get_next()[0])
            except Exception:
                pass
            result["domains"].append({
                "name": domain_name,
                "is_dga_candidate": row[1],
                "first_seen": str(row[2]) if row[2] else None,
                "resolved_by": row[3],
                "resolved_by_pids": row[4],
                "resolved_ips": resolved_ips,
            })
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
            result["external_ips"].append({
                "address": row[0],
                "ports": row[2],
                "connected_by": row[3],
                "connected_by_pids": row[4],
                "country": row[6] or "",
                "isp": row[7] or "",
                "classification": row[8] or "unclassified",
                "provider_name": row[9] or "",
                "reverse_dns": row[10] or "",
            })
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
                result["files"].append({
                    "path": path,
                    "operation": operation,
                    "by_processes": by_procs,
                    "by_pids": by_pids,
                    "timestamp": str(row[3]) if row[3] else None,
                })
        except Exception:
            logger.debug("IOC file query failed for %s", rel_type, exc_info=True)

    return result
