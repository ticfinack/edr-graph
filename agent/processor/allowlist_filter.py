"""Pre-graph allowlist filter.

Removes entities from an ``ExtractedEntities`` batch that match any
graph-filterable allowlist rule *before* they are written to the Kuzu graph.

This prevents allowlisted behaviors from accumulating in the graph at all,
complementing the response-engine allowlist which only suppresses actions.
"""

from __future__ import annotations

import logging

from agent.processor.entity_extractor import ExtractedEntities
from agent.response.baseline import _match_rule

logger = logging.getLogger(__name__)


def filter_entities(entities: ExtractedEntities, rules: list[dict]) -> int:
    """Remove entities matching any allowlist rule.

    Checks process names, IP addresses, domains, and file paths against the
    supplied rules.  When a node is removed, all edges referencing that node
    are also pruned.  Orphaned user nodes (no remaining spawned_edges) are
    cleaned up last.

    Returns the total number of items (nodes + edges) removed.
    """
    if not rules:
        return 0

    removed = 0

    # --- Processes ---
    matched_proc_ids: set[str] = set()
    kept_processes = []
    for proc in entities.processes:
        if any(_match_rule(r, process_name=proc.name) for r in rules):
            matched_proc_ids.add(proc.id)
            removed += 1
            logger.debug("Allowlist filter: removed process %s (%s)", proc.name, proc.id)
        else:
            kept_processes.append(proc)
    entities.processes = kept_processes

    if matched_proc_ids:
        # Remove edges referencing matched processes
        before = len(entities.spawned_edges)
        entities.spawned_edges = [e for e in entities.spawned_edges if e["process_id"] not in matched_proc_ids]
        removed += before - len(entities.spawned_edges)

        before = len(entities.connected_edges)
        entities.connected_edges = [e for e in entities.connected_edges if e["process_id"] not in matched_proc_ids]
        removed += before - len(entities.connected_edges)

        before = len(entities.resolved_edges)
        entities.resolved_edges = [e for e in entities.resolved_edges if e["process_id"] not in matched_proc_ids]
        removed += before - len(entities.resolved_edges)

        before = len(entities.file_edges)
        entities.file_edges = [e for e in entities.file_edges if e["process_id"] not in matched_proc_ids]
        removed += before - len(entities.file_edges)

        before = len(entities.registry_edges)
        entities.registry_edges = [e for e in entities.registry_edges if e["process_id"] not in matched_proc_ids]
        removed += before - len(entities.registry_edges)

    # --- IPs ---
    matched_ip_ids: set[str] = set()
    kept_ips = []
    for ip_node in entities.ips:
        if any(_match_rule(r, dst_ip=ip_node.address) for r in rules):
            matched_ip_ids.add(ip_node.id)
            removed += 1
            logger.debug("Allowlist filter: removed IP %s", ip_node.address)
        else:
            kept_ips.append(ip_node)
    entities.ips = kept_ips

    if matched_ip_ids:
        before = len(entities.connected_edges)
        entities.connected_edges = [e for e in entities.connected_edges if e["ip_id"] not in matched_ip_ids]
        removed += before - len(entities.connected_edges)

        before = len(entities.resolves_to_edges)
        entities.resolves_to_edges = [e for e in entities.resolves_to_edges if e["ip_id"] not in matched_ip_ids]
        removed += before - len(entities.resolves_to_edges)

    # --- Domains ---
    matched_domain_ids: set[str] = set()
    kept_domains = []
    for domain_node in entities.domains:
        if any(_match_rule(r, domain=domain_node.name) for r in rules):
            matched_domain_ids.add(domain_node.id)
            removed += 1
            logger.debug("Allowlist filter: removed domain %s", domain_node.name)
        else:
            kept_domains.append(domain_node)
    entities.domains = kept_domains

    if matched_domain_ids:
        before = len(entities.resolved_edges)
        entities.resolved_edges = [e for e in entities.resolved_edges if e["domain_id"] not in matched_domain_ids]
        removed += before - len(entities.resolved_edges)

        before = len(entities.resolves_to_edges)
        entities.resolves_to_edges = [e for e in entities.resolves_to_edges if e["domain_id"] not in matched_domain_ids]
        removed += before - len(entities.resolves_to_edges)

    # --- Files ---
    matched_file_ids: set[str] = set()
    kept_files = []
    for file_node in entities.files:
        if any(_match_rule(r, file_path=file_node.path) for r in rules):
            matched_file_ids.add(file_node.id)
            removed += 1
            logger.debug("Allowlist filter: removed file %s", file_node.path)
        else:
            kept_files.append(file_node)
    entities.files = kept_files

    if matched_file_ids:
        before = len(entities.file_edges)
        entities.file_edges = [e for e in entities.file_edges if e["file_id"] not in matched_file_ids]
        removed += before - len(entities.file_edges)

    # --- Orphaned users ---
    # Remove user nodes that have no remaining spawned_edges
    if removed > 0 and entities.users:
        referenced_user_ids = {e["user_id"] for e in entities.spawned_edges}
        before = len(entities.users)
        entities.users = [u for u in entities.users if u.id in referenced_user_ids]
        removed += before - len(entities.users)

    return removed


def has_entities(entities: ExtractedEntities) -> bool:
    """Return True if the entities container has any nodes left."""
    return bool(
        entities.processes
        or entities.ips
        or entities.domains
        or entities.files
        or entities.users
        or entities.registry_keys
    )
