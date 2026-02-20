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
