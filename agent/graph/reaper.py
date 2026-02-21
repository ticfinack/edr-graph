"""TTL reaper for the KùzuDB graph.

Prunes edges older than the configured TTL, then removes orphaned nodes
(nodes with zero remaining edges).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import kuzu

from agent import metrics
from agent.graph.pid_index import get_pid_index

logger = logging.getLogger(__name__)

ALL_EDGE_TYPES = [
    "SPAWNED",
    "CONNECTED_TO",
    "RESOLVED",
    "RESOLVES_TO",
    "CREATED_FILE",
    "MODIFIED_FILE",
    "READ_FILE",
    "DELETED_FILE",
    "CREATED_REG",
    "MODIFIED_REG",
    "DELETED_REG",
    "LISTENING_ON",
]

# Node types and the edge directions to check for remaining connections.
# Tuples of (direction, edge_type) where:
#   "in"  = ()-[e:TYPE]->(node)
#   "out" = (node)-[e:TYPE]->()
_NODE_EDGE_CHECKS: dict[str, list[tuple[str, str]]] = {
    "IP": [
        ("in", "CONNECTED_TO"),
        ("in", "RESOLVES_TO"),
        ("in", "LISTENING_ON"),
    ],
    "Domain": [
        ("in", "RESOLVED"),
        ("out", "RESOLVES_TO"),
    ],
    "File": [
        ("in", "CREATED_FILE"),
        ("in", "MODIFIED_FILE"),
        ("in", "READ_FILE"),
        ("in", "DELETED_FILE"),
    ],
    "RegistryKey": [
        ("in", "CREATED_REG"),
        ("in", "MODIFIED_REG"),
        ("in", "DELETED_REG"),
    ],
    "Process": [
        ("in", "SPAWNED"),
        ("out", "CONNECTED_TO"),
        ("out", "RESOLVED"),
        ("out", "CREATED_FILE"),
        ("out", "MODIFIED_FILE"),
        ("out", "READ_FILE"),
        ("out", "DELETED_FILE"),
        ("out", "CREATED_REG"),
        ("out", "MODIFIED_REG"),
        ("out", "DELETED_REG"),
        ("out", "LISTENING_ON"),
    ],
    "User": [
        ("out", "SPAWNED"),
    ],
}


def prune_old_edges(conn: kuzu.Connection, ttl_hours: int) -> int:
    """Delete graph edges older than *ttl_hours* and clean up orphaned nodes.

    Returns the total number of edges + nodes deleted.
    """
    cutoff = datetime.now() - timedelta(hours=ttl_hours)

    total_deleted = 0

    for edge_type in ALL_EDGE_TYPES:
        try:
            # Count first — KùzuDB DELETE doesn't return affected row counts
            count_result = conn.execute(
                f"MATCH ()-[e:{edge_type}]->() WHERE e.timestamp < $cutoff RETURN COUNT(e)",
                {"cutoff": cutoff},
            )
            count = count_result.get_next()[0] if count_result.has_next() else 0
            if count > 0:
                conn.execute(
                    f"MATCH ()-[e:{edge_type}]->() WHERE e.timestamp < $cutoff DELETE e",
                    {"cutoff": cutoff},
                )
                total_deleted += count
        except Exception:
            logger.debug("Reaper: failed to prune %s edges", edge_type, exc_info=True)

    orphaned = _cleanup_orphaned_nodes(conn)
    total_deleted += orphaned

    if total_deleted:
        metrics.graph_reaper_pruned.inc(total_deleted)

    return total_deleted


def _cleanup_orphaned_nodes(conn: kuzu.Connection) -> int:
    """Remove nodes that have zero remaining edges after TTL pruning.

    Returns the count of deleted nodes.
    """
    deleted = 0
    deleted_process_ids: list[str] = []

    for label, checks in _NODE_EDGE_CHECKS.items():
        try:
            result = conn.execute(f"MATCH (n:{label}) RETURN n.id")
            node_ids: list[str] = []
            while result.has_next():
                node_ids.append(result.get_next()[0])

            for node_id in node_ids:
                has_edges = False
                for direction, edge_type in checks:
                    try:
                        if direction == "in":
                            q = f"MATCH ()-[e:{edge_type}]->(n:{label} {{id: $id}}) RETURN COUNT(e)"
                        else:
                            q = f"MATCH (n:{label} {{id: $id}})-[e:{edge_type}]->() RETURN COUNT(e)"
                        r = conn.execute(q, {"id": node_id})
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
                    if label == "Process":
                        deleted_process_ids.append(node_id)
        except Exception:
            logger.debug("Reaper: orphaned %s cleanup failed", label, exc_info=True)

    # Synchronize PID index
    if deleted_process_ids:
        get_pid_index().remove_nodes(deleted_process_ids)

    return deleted
