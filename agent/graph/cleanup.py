"""Retroactive graph cleanup for allowlist rules.

When a new allowlist rule is added, ``purge_by_rule`` removes existing
graph nodes (and all their incident edges via ``DETACH DELETE``) that
match the rule pattern.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging

import kuzu

logger = logging.getLogger(__name__)


def purge_by_rule(conn: kuzu.Connection, rule_type: str, pattern: str) -> int:
    """Delete graph nodes matching a single allowlist rule.

    Uses ``DETACH DELETE`` which automatically removes all incident edges
    when a node is deleted.

    Note: This is a best-effort retroactive purge.  There is a small TOCTOU
    window between the SELECT scan and the subsequent DELETEs during which
    the processor thread may insert new matching nodes.  The ongoing
    ``filter_entities`` pre-graph filter (driven by the AllowlistRuleCache)
    provides the continuous guarantee that matching entities are excluded
    going forward.

    Returns the number of nodes deleted.
    """
    handlers = {
        "process_name": _purge_process_name,
        "dst_ip": _purge_dst_ip,
        "dst_cidr": _purge_dst_cidr,
        "domain": _purge_domain,
        "file_path": _purge_file_path,
    }
    handler = handlers.get(rule_type)
    if handler is None:
        logger.debug("purge_by_rule: unsupported rule_type %s", rule_type)
        return 0
    try:
        return handler(conn, pattern)
    except Exception:
        logger.exception("purge_by_rule failed for %s / %s", rule_type, pattern)
        return 0


def _purge_process_name(conn: kuzu.Connection, pattern: str) -> int:
    """Remove Process nodes whose name matches *pattern* (fnmatch glob)."""
    result = conn.execute("MATCH (p:Process) RETURN p.id, p.name")
    to_delete: list[str] = []
    while result.has_next():
        row = result.get_next()
        proc_id, proc_name = row[0], row[1]
        if proc_name and fnmatch.fnmatch(proc_name.lower(), pattern.lower()):
            to_delete.append(proc_id)

    for proc_id in to_delete:
        conn.execute(
            "MATCH (p:Process {id: $id}) DETACH DELETE p",
            {"id": proc_id},
        )
    if to_delete:
        logger.info("Purged %d Process nodes matching %r", len(to_delete), pattern)
    return len(to_delete)


def _purge_dst_ip(conn: kuzu.Connection, pattern: str) -> int:
    """Remove an IP node with an exact address match."""
    result = conn.execute(
        "MATCH (ip:IP {address: $addr}) RETURN ip.id",
        {"addr": pattern},
    )
    count = 0
    while result.has_next():
        ip_id = result.get_next()[0]
        conn.execute(
            "MATCH (ip:IP {id: $id}) DETACH DELETE ip",
            {"id": ip_id},
        )
        count += 1
    if count:
        logger.info("Purged %d IP nodes matching %r", count, pattern)
    return count


def _purge_dst_cidr(conn: kuzu.Connection, pattern: str) -> int:
    """Remove IP nodes whose address falls within the CIDR range."""
    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        logger.warning("purge_by_rule: invalid CIDR %r", pattern)
        return 0

    result = conn.execute("MATCH (ip:IP) RETURN ip.id, ip.address")
    to_delete: list[str] = []
    while result.has_next():
        row = result.get_next()
        ip_id, ip_addr = row[0], row[1]
        if ip_addr:
            try:
                if ipaddress.ip_address(ip_addr) in network:
                    to_delete.append(ip_id)
            except ValueError:
                continue

    for ip_id in to_delete:
        conn.execute(
            "MATCH (ip:IP {id: $id}) DETACH DELETE ip",
            {"id": ip_id},
        )
    if to_delete:
        logger.info("Purged %d IP nodes in CIDR %s", len(to_delete), pattern)
    return len(to_delete)


def _purge_domain(conn: kuzu.Connection, pattern: str) -> int:
    """Remove a Domain node with an exact (case-insensitive) name match."""
    domain_lower = pattern.lower()
    result = conn.execute(
        "MATCH (d:Domain {name: $name}) RETURN d.id",
        {"name": domain_lower},
    )
    count = 0
    while result.has_next():
        domain_id = result.get_next()[0]
        conn.execute(
            "MATCH (d:Domain {id: $id}) DETACH DELETE d",
            {"id": domain_id},
        )
        count += 1
    if count:
        logger.info("Purged %d Domain nodes matching %r", count, pattern)
    return count


def _purge_file_path(conn: kuzu.Connection, pattern: str) -> int:
    """Remove File nodes whose path matches *pattern* (fnmatch glob)."""
    result = conn.execute("MATCH (f:File) RETURN f.id, f.path")
    to_delete: list[str] = []
    while result.has_next():
        row = result.get_next()
        file_id, file_path = row[0], row[1]
        if file_path and fnmatch.fnmatch(file_path, pattern):
            to_delete.append(file_id)

    for file_id in to_delete:
        conn.execute(
            "MATCH (f:File {id: $id}) DETACH DELETE f",
            {"id": file_id},
        )
    if to_delete:
        logger.info("Purged %d File nodes matching %r", len(to_delete), pattern)
    return len(to_delete)


# ── Baseline-gated retroactive purge ─────────────────────────────────────


def purge_baselined_edges(conn: kuzu.Connection, cache) -> int:
    """Retroactive purge of baselined edges from the graph.

    For each Process node, checks its CONNECTED_TO, RESOLVED, and file edges
    against the baseline cache.  Deletes matched edges individually (not
    DETACH DELETE) to preserve nodes that have other non-baselined edges.

    After all process edges are scanned, cleans up orphaned IP/Domain/File
    nodes (nodes with zero remaining edges).

    Returns the total number of items (edges + orphaned nodes) deleted.
    """
    if not cache.has_entries():
        return 0

    deleted = 0

    # Get all processes
    try:
        result = conn.execute("MATCH (p:Process) RETURN p.name, p.id")
    except Exception:
        logger.exception("purge_baselined_edges: failed to query processes")
        return 0

    processes: list[tuple[str, str]] = []
    while result.has_next():
        row = result.get_next()
        processes.append((row[0], row[1]))  # (name, id)

    for proc_name, proc_id in processes:
        if not proc_name:
            continue

        # Check CONNECTED_TO edges (Process -> IP)
        try:
            result = conn.execute(
                "MATCH (p:Process {id: $pid})-[e:CONNECTED_TO]->(ip:IP) RETURN DISTINCT ip.address",
                {"pid": proc_id},
            )
            while result.has_next():
                ip_addr = result.get_next()[0]
                if cache.is_gated(proc_name, "network", ip_addr):
                    conn.execute(
                        "MATCH (p:Process {id: $pid})-[e:CONNECTED_TO]->(ip:IP {address: $addr}) DELETE e",
                        {"pid": proc_id, "addr": ip_addr},
                    )
                    deleted += 1
        except Exception:
            logger.debug(
                "purge_baselined_edges: CONNECTED_TO scan failed for %s",
                proc_id,
                exc_info=True,
            )

        # Check RESOLVED edges (Process -> Domain)
        try:
            result = conn.execute(
                "MATCH (p:Process {id: $pid})-[e:RESOLVED]->(d:Domain) RETURN DISTINCT d.name",
                {"pid": proc_id},
            )
            while result.has_next():
                domain_name = result.get_next()[0]
                if cache.is_gated(proc_name, "dns", domain_name):
                    conn.execute(
                        "MATCH (p:Process {id: $pid})-[e:RESOLVED]->(d:Domain {name: $name}) DELETE e",
                        {"pid": proc_id, "name": domain_name},
                    )
                    deleted += 1
        except Exception:
            logger.debug(
                "purge_baselined_edges: RESOLVED scan failed for %s",
                proc_id,
                exc_info=True,
            )

        # Check file edges (Process -> File)
        for rel_type in ("CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE"):
            try:
                result = conn.execute(
                    f"MATCH (p:Process {{id: $pid}})-[e:{rel_type}]->(f:File) RETURN DISTINCT f.path",
                    {"pid": proc_id},
                )
                while result.has_next():
                    file_path = result.get_next()[0]
                    if cache.is_gated(proc_name, "file", file_path):
                        conn.execute(
                            f"MATCH (p:Process {{id: $pid}})-[e:{rel_type}]->(f:File {{path: $path}}) DELETE e",
                            {"pid": proc_id, "path": file_path},
                        )
                        deleted += 1
            except Exception:
                logger.debug(
                    "purge_baselined_edges: %s scan failed for %s",
                    rel_type,
                    proc_id,
                    exc_info=True,
                )

    # Clean up orphaned target nodes (no remaining edges)
    deleted += _cleanup_orphaned_targets(conn, "IP", "address", ["CONNECTED_TO", "RESOLVES_TO"])
    deleted += _cleanup_orphaned_targets(conn, "Domain", "name", ["RESOLVED", "RESOLVES_TO"])
    deleted += _cleanup_orphaned_targets(
        conn, "File", "path", ["CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE"]
    )

    if deleted:
        logger.info("Purged %d baselined items from graph", deleted)

    return deleted


def _cleanup_orphaned_targets(
    conn: kuzu.Connection,
    label: str,
    display_prop: str,
    edge_types: list[str],
) -> int:
    """Delete nodes of ``label`` that have zero remaining incoming edges.

    Checks each node for any incoming edges of the given types.  Uses
    individual DELETE (not DETACH DELETE) since we've already confirmed
    there are no edges.

    Returns the count of deleted nodes.
    """
    deleted = 0
    try:
        result = conn.execute(f"MATCH (n:{label}) RETURN n.id")
        node_ids: list[str] = []
        while result.has_next():
            node_ids.append(result.get_next()[0])

        for node_id in node_ids:
            has_edges = False
            for et in edge_types:
                try:
                    r = conn.execute(
                        f"MATCH ()-[e:{et}]->(n:{label} {{id: $id}}) RETURN COUNT(e)",
                        {"id": node_id},
                    )
                    if r.has_next() and r.get_next()[0] > 0:
                        has_edges = True
                        break
                except Exception:
                    has_edges = True  # Assume has edges on error
                    break

            if not has_edges:
                conn.execute(
                    f"MATCH (n:{label} {{id: $id}}) DETACH DELETE n",
                    {"id": node_id},
                )
                deleted += 1
    except Exception:
        logger.debug("Orphaned %s cleanup failed", label, exc_info=True)

    return deleted
