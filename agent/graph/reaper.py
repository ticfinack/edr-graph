"""TTL reaper for the KùzuDB graph.

Prunes edges older than the configured TTL, then removes orphaned nodes
(nodes with zero remaining edges).  Supports emergency edge-only pruning
for memory-pressure situations.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

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

# When the DB directory exceeds this size, the reaper triggers an
# emergency edge-only prune (skipping the expensive orphan cleanup).
DB_SIZE_EMERGENCY_THRESHOLD_MB = 250

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


def get_rss_mb() -> float:
    """Return the current process RSS in MB.

    Uses /proc/self/status on Linux (zero overhead, current RSS).
    Falls back to resource.getrusage on macOS (peak RSS — close enough
    for pressure detection, and avoids psutil import issues in tests).
    Returns 0.0 on any error.
    """
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024  # kB -> MB
    except (OSError, ValueError, IndexError):
        pass
    try:
        import resource

        rusage = resource.getrusage(resource.RUSAGE_SELF)
        if sys.platform == "darwin":
            return rusage.ru_maxrss / (1024 * 1024)  # bytes -> MB on macOS
        return rusage.ru_maxrss / 1024  # kB -> MB on other Unix
    except Exception:
        return 0.0


def get_memory_limit_mb() -> float:
    """Return the effective memory limit (cgroup or physical RAM) in MB.

    Prefers cgroup limit (for containerized/systemd environments), falls
    back to physical RAM via os.sysconf (avoids psutil import issues).
    Returns 0.0 on any error.
    """
    from agent.config import _read_cgroup_memory_limit

    cgroup_bytes = _read_cgroup_memory_limit()
    if cgroup_bytes is not None:
        return cgroup_bytes / (1024 * 1024)
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return (pages * page_size) / (1024 * 1024)
    except (ValueError, OSError, AttributeError):
        return 0.0


def measure_db_dir_size_mb(graph_path: Path) -> float:
    """Return the total size of the graph database files in MB.

    Handles both directory-based (Kuzu default) and single-file storage.
    Also includes the WAL file (<path>.wal) if present.
    Returns 0.0 on any error.
    """
    try:
        total = 0
        if graph_path.is_dir():
            total = sum(f.stat().st_size for f in graph_path.rglob("*") if f.is_file())
        elif graph_path.is_file():
            total = graph_path.stat().st_size
        # Include WAL file (same name + .wal suffix)
        wal_path = graph_path.parent / (graph_path.name + ".wal")
        if wal_path.is_file():
            total += wal_path.stat().st_size
        return total / (1024 * 1024)
    except Exception:
        return 0.0


def _prune_edges(conn: kuzu.Connection, ttl_hours: float) -> int:
    """Delete edges older than *ttl_hours*. Returns the count of edges deleted."""
    cutoff = datetime.now() - timedelta(hours=ttl_hours)
    total_deleted = 0

    for edge_type in ALL_EDGE_TYPES:
        try:
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

    return total_deleted


def prune_edges_only(conn: kuzu.Connection, ttl_hours: float) -> int:
    """Fast edge-only prune — skips orphan cleanup entirely.

    Used for emergency pressure prunes where speed matters.
    Returns the count of edges deleted.
    """
    deleted = _prune_edges(conn, ttl_hours)
    if deleted:
        metrics.graph_reaper_pruned.inc(deleted)
    return deleted


def prune_old_edges(conn: kuzu.Connection, ttl_hours: float) -> int:
    """Delete graph edges older than *ttl_hours* and clean up orphaned nodes.

    Returns the total number of edges + nodes deleted.
    """
    total_deleted = _prune_edges(conn, ttl_hours)

    orphaned = _cleanup_orphaned_nodes_batched(conn)
    total_deleted += orphaned

    if total_deleted:
        metrics.graph_reaper_pruned.inc(total_deleted)

    return total_deleted


# Edge types that tend to be high-volume (network, file activity)
_HIGH_VOLUME_EDGE_TYPES = [
    "CONNECTED_TO",
    "RESOLVED",
    "CREATED_FILE",
    "MODIFIED_FILE",
    "READ_FILE",
]


def prune_high_degree_nodes(
    conn: kuzu.Connection,
    edge_threshold: int = 100,
    keep_pct: float = 0.80,
) -> int:
    """Prune oldest edges from high-degree Process nodes (frequency-based).

    For each high-volume edge type, finds Process nodes with more than
    *edge_threshold* outgoing edges and deletes the oldest (1 - keep_pct)
    fraction.  This targets "chatty" processes (e.g., web scrapers, DNS
    resolvers) that dominate graph size without carrying unique signals.

    Returns the total number of edges deleted.
    """
    total_deleted = 0

    for edge_type in _HIGH_VOLUME_EDGE_TYPES:
        try:
            # Find high-degree Process nodes for this edge type
            result = conn.execute(
                f"MATCH (p:Process)-[e:{edge_type}]->() "
                f"WITH p.id AS pid, COUNT(e) AS deg "
                f"WHERE deg > $threshold "
                f"RETURN pid, deg",
                {"threshold": edge_threshold},
            )

            targets: list[tuple[str, int]] = []
            while result.has_next():
                row = result.get_next()
                targets.append((row[0], row[1]))

            for pid, degree in targets:
                prune_count = int(degree * (1.0 - keep_pct))
                if prune_count < 1:
                    continue
                try:
                    # Delete the oldest edges for this process
                    conn.execute(
                        f"MATCH (p:Process {{id: $pid}})-[e:{edge_type}]->() "
                        f"WITH e ORDER BY e.timestamp ASC LIMIT $limit "
                        f"DELETE e",
                        {"pid": pid, "limit": prune_count},
                    )
                    total_deleted += prune_count
                except Exception:
                    logger.debug(
                        "Reaper: high-degree prune failed for %s on %s",
                        edge_type, pid, exc_info=True,
                    )

        except Exception:
            logger.debug("Reaper: high-degree scan failed for %s", edge_type, exc_info=True)

    if total_deleted:
        logger.info("Reaper: pruned %d edges from high-degree nodes", total_deleted)
        metrics.graph_reaper_pruned.inc(total_deleted)

    return total_deleted


def _cleanup_orphaned_nodes_batched(conn: kuzu.Connection, batch_size: int = 500) -> int:
    """Remove orphaned nodes in batches to avoid scanning all nodes at once.

    Uses per-node edge count checks (NOT EXISTS subqueries segfault Kuzu 0.11.x).
    Processes each node type in LIMIT batches to bound memory and query time.
    Returns the count of deleted nodes.
    """
    deleted = 0
    deleted_process_ids: list[str] = []

    for label, checks in _NODE_EDGE_CHECKS.items():
        try:
            # Fetch node IDs in batches using SKIP/LIMIT
            offset = 0
            while True:
                result = conn.execute(
                    f"MATCH (n:{label}) RETURN n.id SKIP $skip LIMIT $limit",
                    {"skip": offset, "limit": batch_size},
                )
                node_ids: list[str] = []
                while result.has_next():
                    node_ids.append(result.get_next()[0])

                if not node_ids:
                    break

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
                        try:
                            conn.execute(
                                f"MATCH (n:{label} {{id: $id}}) DETACH DELETE n",
                                {"id": node_id},
                            )
                            deleted += 1
                            if label == "Process":
                                deleted_process_ids.append(node_id)
                        except Exception:
                            logger.debug("Reaper: failed to delete orphan %s %s", label, node_id, exc_info=True)

                # Advance offset (minus any nodes we deleted in this batch)
                batch_deleted = sum(1 for nid in node_ids if nid in deleted_process_ids) if label == "Process" else 0
                # If we deleted nodes, offset stays (rows shifted down); otherwise advance
                if len(node_ids) < batch_size:
                    break
                offset += batch_size - batch_deleted

        except Exception:
            logger.debug("Reaper: orphaned %s cleanup failed", label, exc_info=True)

    # Synchronize PID index
    if deleted_process_ids:
        get_pid_index().remove_nodes(deleted_process_ids)

    return deleted
