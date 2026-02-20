"""Attribute file events to processes using psutil open_files().

FSEvents (macOS) doesn't report which process modified a file. This module
builds a periodic cache of directory→process mappings from psutil to infer
the likely owning process for file events with PID 0.

The cache refreshes every 30 seconds and maps parent directories to processes
that have files open there. When multiple processes match, the most specific
(deepest directory) match wins.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import psutil

logger = logging.getLogger(__name__)


@dataclass
class FileOwner:
    pid: int
    name: str
    parent_pid: int


class FileAttributionCache:
    """Maps directories to processes that have open files there."""

    def __init__(self, refresh_interval: float = 30.0) -> None:
        self._refresh_interval = refresh_interval
        self._dir_to_procs: dict[str, list[FileOwner]] = {}
        self._lock = threading.Lock()
        self._last_refresh = 0.0
        self._agent_pid = 0

    def set_agent_pid(self, pid: int) -> None:
        self._agent_pid = pid

    def lookup(self, file_path: str) -> FileOwner | None:
        """Find the most likely process that owns a file.

        Walks up the directory tree looking for processes with open files
        in that directory. Returns the first match (deepest dir wins).
        """
        self._maybe_refresh()

        with self._lock:
            # Walk up directory tree for best match
            path = file_path
            for _ in range(5):  # max 5 levels up
                parent = path.rsplit("/", 1)[0] if "/" in path else ""
                if not parent:
                    break
                procs = self._dir_to_procs.get(parent)
                if procs:
                    # Return the first non-system process
                    for p in procs:
                        if p.pid > 0 and p.pid != self._agent_pid:
                            return p
                path = parent
        return None

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return
        self._last_refresh = now
        # Run in background to avoid blocking
        t = threading.Thread(target=self._refresh, daemon=True, name="file-attr-refresh")
        t.start()

    def _refresh(self) -> None:
        dir_map: dict[str, list[FileOwner]] = {}
        count = 0
        try:
            for proc in psutil.process_iter(["pid", "name", "ppid"]):
                try:
                    info = proc.info
                    pid = info["pid"]
                    if pid <= 1 or pid == self._agent_pid:
                        continue
                    files = proc.open_files()
                    if not files:
                        continue
                    owner = FileOwner(
                        pid=pid,
                        name=info["name"] or "",
                        parent_pid=info["ppid"] or 0,
                    )
                    seen_dirs: set[str] = set()
                    for f in files:
                        parent_dir = f.path.rsplit("/", 1)[0] if "/" in f.path else ""
                        if parent_dir and parent_dir not in seen_dirs:
                            seen_dirs.add(parent_dir)
                            dir_map.setdefault(parent_dir, []).append(owner)
                            count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            logger.debug("File attribution refresh failed", exc_info=True)

        with self._lock:
            self._dir_to_procs = dir_map
        logger.debug("File attribution cache refreshed: %d dir->process mappings", count)


# Module-level singleton
_cache: FileAttributionCache | None = None


def get_file_attribution_cache() -> FileAttributionCache:
    global _cache
    if _cache is None:
        _cache = FileAttributionCache()
    return _cache
