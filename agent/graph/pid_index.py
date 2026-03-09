"""In-memory PID-to-node-ID index for O(1) process lookups.

Kuzu only indexes the primary key (``id STRING``).  All dashboard queries
filter on ``pid INT64``, which causes full table scans across 500K+ rows.

This module maintains an in-memory mapping so queries can use primary-key
hash lookups instead of sequential scans.
"""

from __future__ import annotations

import logging
import threading

import kuzu

logger = logging.getLogger(__name__)


class PidIndex:
    """Thread-safe in-memory index: PID <-> node IDs.

    Supports multiple node IDs per PID (PID reuse across different
    create_time epochs).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # pid -> list of node IDs (latest appended last)
        self._pid_to_ids: dict[int, list[str]] = {}
        # parent_pid -> set of child PIDs
        self._ppid_to_children: dict[int, set[int]] = {}
        # pid -> parent_pid (for chain walking)
        self._pid_to_ppid: dict[int, int] = {}
        # pid -> process name
        self._pid_to_name: dict[int, str] = {}
        self._built = False

    def build(self, conn: kuzu.Connection) -> None:
        """One-time scan of all Process nodes to populate the index."""
        pid_to_ids: dict[int, list[str]] = {}
        ppid_to_children: dict[int, set[int]] = {}
        pid_to_ppid: dict[int, int] = {}
        pid_to_name: dict[int, str] = {}
        try:
            result = conn.execute("MATCH (p:Process) RETURN p.id, p.pid, p.parent_pid, p.name")
            count = 0
            while result.has_next():
                row = result.get_next()
                node_id, pid, ppid, name = row[0], row[1], row[2], row[3]
                if pid is None:
                    continue
                pid_to_ids.setdefault(pid, []).append(node_id)
                if ppid and ppid > 0:
                    ppid_to_children.setdefault(ppid, set()).add(pid)
                    pid_to_ppid[pid] = ppid
                if name:
                    pid_to_name[pid] = name
                count += 1

            with self._lock:
                self._pid_to_ids = pid_to_ids
                self._ppid_to_children = ppid_to_children
                self._pid_to_ppid = pid_to_ppid
                self._pid_to_name = pid_to_name
                self._built = True

            logger.info(
                "PID index built: %d processes, %d parent groups",
                count,
                len(ppid_to_children),
            )
        except Exception:
            logger.warning("Failed to build PID index", exc_info=True)

    def on_upsert(self, node_id: str, pid: int, parent_pid: int, name: str = "") -> None:
        """Called by GraphBuilder after upserting a Process node."""
        with self._lock:
            ids = self._pid_to_ids.setdefault(pid, [])
            if node_id not in ids:
                ids.append(node_id)
            if parent_pid and parent_pid > 0:
                self._ppid_to_children.setdefault(parent_pid, set()).add(pid)
                self._pid_to_ppid[pid] = parent_pid
            if name:
                self._pid_to_name[pid] = name

    def remove_nodes(self, node_ids: list[str]) -> int:
        """Remove deleted node IDs from the index. Returns count evicted."""
        if not node_ids:
            return 0
        to_remove = set(node_ids)
        evicted = 0
        with self._lock:
            # Evict from pid_to_ids
            empty_pids: list[int] = []
            for pid, ids in self._pid_to_ids.items():
                before = len(ids)
                ids[:] = [nid for nid in ids if nid not in to_remove]
                evicted += before - len(ids)
                if not ids:
                    empty_pids.append(pid)
            for pid in empty_pids:
                del self._pid_to_ids[pid]
                # Also clean ppid_to_children entries pointing to this pid
                for children in self._ppid_to_children.values():
                    children.discard(pid)
                # Clean up ppid and name mappings
                self._pid_to_ppid.pop(pid, None)
                self._pid_to_name.pop(pid, None)

            # Clean empty parent groups
            empty_ppids = [pp for pp, ch in self._ppid_to_children.items() if not ch]
            for pp in empty_ppids:
                del self._ppid_to_children[pp]

        if evicted:
            logger.info("PID index: evicted %d stale node_ids", evicted)
        return evicted

    @staticmethod
    def _extract_epoch(node_id: str) -> float:
        """Extract create_time epoch from node_id 'hostname:pid:epoch'."""
        try:
            return float(node_id.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return 0.0

    def get_node_id_at_time(self, pid: int, event_ts: float) -> str | None:
        """Get the node ID for the PID instance active at event_ts.

        Picks the node whose create_time is the largest value <= event_ts
        (most recent incarnation before the event occurred).
        """
        with self._lock:
            ids = self._pid_to_ids.get(pid, [])
            if not ids:
                return None
            best = None
            best_epoch = 0.0
            for nid in ids:
                epoch = self._extract_epoch(nid)
                if epoch <= event_ts and epoch > best_epoch:
                    best = nid
                    best_epoch = epoch
            return best  # None if all incarnations are newer than event_ts

    def get_node_ids(self, pid: int) -> list[str]:
        """Get all node IDs for a PID, sorted newest-first by epoch."""
        with self._lock:
            ids = self._pid_to_ids.get(pid, [])
            if len(ids) <= 1:
                return list(ids)
            return sorted(ids, key=self._extract_epoch, reverse=True)

    def get_latest_node_id(self, pid: int) -> str | None:
        """Get the most recently created node ID for a PID (by epoch)."""
        with self._lock:
            ids = self._pid_to_ids.get(pid)
            if not ids:
                return None
            if len(ids) == 1:
                return ids[0]
            return max(ids, key=self._extract_epoch)

    def get_children_pids(self, parent_pid: int) -> list[int]:
        """Get all child PIDs for a parent PID."""
        with self._lock:
            return list(self._ppid_to_children.get(parent_pid, set()))

    def get_parent_pid(self, pid: int) -> int | None:
        """Get the parent PID for a process, or None if unknown/root."""
        with self._lock:
            ppid = self._pid_to_ppid.get(pid)
            if ppid and ppid > 0:
                return ppid
            return None

    def get_name(self, pid: int) -> str:
        """Get the process name for a PID, or empty string if unknown."""
        with self._lock:
            return self._pid_to_name.get(pid, "")

    def update_from_entities(self, entities) -> None:
        """Update index directly from extracted entities (decoupled from Kuzu)."""
        for proc in entities.processes:
            self.on_upsert(proc.id, proc.pid, proc.parent_pid or 0, proc.name)

    def build_from_ledger(self, ledger_reader) -> None:
        """Build index from ledger ProcessActivity entities instead of Kuzu scan."""
        import time as _time

        pid_to_ids: dict[int, list[str]] = {}
        ppid_to_children: dict[int, set[int]] = {}
        pid_to_ppid: dict[int, int] = {}
        pid_to_name: dict[int, str] = {}
        count = 0

        try:
            now = _time.time()
            start = now - (2 * 3600)  # Last 2h (was 24h — caused OOM on large ledgers)
            for entities in ledger_reader.iter_entities(start, now):
                for proc in entities.processes:
                    if proc.pid is None:
                        continue
                    pid_to_ids.setdefault(proc.pid, []).append(proc.id)
                    ppid = proc.parent_pid or 0
                    if ppid > 0:
                        ppid_to_children.setdefault(ppid, set()).add(proc.pid)
                        pid_to_ppid[proc.pid] = ppid
                    if proc.name:
                        pid_to_name[proc.pid] = proc.name
                    count += 1

            # Deduplicate node IDs per PID
            for pid in pid_to_ids:
                pid_to_ids[pid] = list(dict.fromkeys(pid_to_ids[pid]))

            with self._lock:
                self._pid_to_ids = pid_to_ids
                self._ppid_to_children = ppid_to_children
                self._pid_to_ppid = pid_to_ppid
                self._pid_to_name = pid_to_name
                self._built = True

            logger.info(
                "PID index built from ledger: %d process entries, %d parent groups",
                count,
                len(ppid_to_children),
            )
        except Exception:
            logger.warning("Failed to build PID index from ledger", exc_info=True)

    @property
    def is_built(self) -> bool:
        return self._built


# Module-level singleton
_index = PidIndex()


def get_pid_index() -> PidIndex:
    return _index
