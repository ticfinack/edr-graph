"""Pre-graph baseline gate.

Filters edges from an ExtractedEntities batch that match the behavior
baseline, preventing known-good behaviors from entering the graph while
still allowing novel behaviors through.

Unlike the allowlist filter (which removes entire nodes by rule), this
operates at the edge level: only specific process->target edges are gated.
Process and User nodes are always kept to preserve chain/ancestry context.
"""

from __future__ import annotations

import logging

from agent.processor.entity_extractor import ExtractedEntities
from agent.response.baseline import BaselineGateCache

logger = logging.getLogger(__name__)


def gate_baselined_edges(entities: ExtractedEntities, cache: BaselineGateCache) -> int:
    """Remove edges matching baseline entries.

    Checks connected_edges (network), resolved_edges (dns), and file_edges
    against the baseline cache.  Removes matched edges and cleans up orphaned
    target nodes (IPs, Domains, Files) that have no remaining edges in this
    batch.

    Process and User nodes are always kept for chain context.

    Returns the count of removed items (edges + orphaned nodes).
    """
    if not cache.has_entries():
        return 0

    removed = 0

    # Build process_id -> process_name map
    proc_names: dict[str, str] = {}
    for proc in entities.processes:
        proc_names[proc.id] = proc.name

    # --- Gate connected_edges (network) ---
    kept_connected = []
    for edge in entities.connected_edges:
        proc_name = proc_names.get(edge["process_id"], "")
        if proc_name and cache.is_gated(proc_name, "network", edge["ip_id"]):
            removed += 1
        else:
            kept_connected.append(edge)
    entities.connected_edges = kept_connected

    # --- Gate resolved_edges (dns) ---
    kept_resolved = []
    for edge in entities.resolved_edges:
        proc_name = proc_names.get(edge["process_id"], "")
        if proc_name and cache.is_gated(proc_name, "dns", edge["domain_id"]):
            removed += 1
        else:
            kept_resolved.append(edge)
    entities.resolved_edges = kept_resolved

    # --- Gate file_edges ---
    kept_file = []
    for edge in entities.file_edges:
        proc_name = proc_names.get(edge["process_id"], "")
        if proc_name and cache.is_gated(proc_name, "file", edge["file_id"]):
            removed += 1
        else:
            kept_file.append(edge)
    entities.file_edges = kept_file

    if removed == 0:
        return 0

    # --- Clean up orphaned target nodes ---
    # Collect all target IDs still referenced by remaining edges
    referenced_ips: set[str] = set()
    for e in entities.connected_edges:
        referenced_ips.add(e["ip_id"])
    for e in entities.resolves_to_edges:
        referenced_ips.add(e["ip_id"])

    referenced_domains: set[str] = set()
    for e in entities.resolved_edges:
        referenced_domains.add(e["domain_id"])
    for e in entities.resolves_to_edges:
        referenced_domains.add(e["domain_id"])

    referenced_files: set[str] = set()
    for e in entities.file_edges:
        referenced_files.add(e["file_id"])

    # Remove orphaned IP nodes
    before = len(entities.ips)
    entities.ips = [ip for ip in entities.ips if ip.id in referenced_ips]
    removed += before - len(entities.ips)

    # Remove orphaned Domain nodes
    before = len(entities.domains)
    entities.domains = [d for d in entities.domains if d.id in referenced_domains]
    removed += before - len(entities.domains)

    # Remove orphaned File nodes
    before = len(entities.files)
    entities.files = [f for f in entities.files if f.id in referenced_files]
    removed += before - len(entities.files)

    return removed
