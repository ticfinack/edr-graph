"""macOS FSEvents file I/O collector using watchdog.

Uses the macOS FSEvents API (via watchdog) to monitor filesystem changes.
FSEvents is the same API that Spotlight and Time Machine use — no entitlement required.

Limitations:
- FSEvents does NOT provide the PID that made the change (that requires Endpoint Security)
- Events are coalesced by the OS within a configurable latency window
- Rapid duplicate events for the same path are deduplicated within 1 second
"""

from __future__ import annotations

import fnmatch
import logging
import os
import socket
import sys
import threading
import time
from datetime import UTC, datetime

from .base import Collector, RawEvent

if sys.platform != "darwin":
    raise ImportError("FSEvents collector is macOS-only")

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

# Default watched paths
DEFAULT_WATCHED_PATHS = [
    "/Users/",
    "/tmp/",
    "/var/tmp/",
    "/etc/",
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/Applications/",
]

# Default excluded path patterns (glob matching)
DEFAULT_EXCLUDED_PATHS = [
    "/Users/*/Library/Caches/*",
    "/Users/*/Library/Logs/*",
    "/Users/*/.Trash/*",
    "/tmp/com.apple.*",
]

# Default excluded extensions
DEFAULT_EXCLUDED_EXTENSIONS = frozenset({
    ".log", ".tmp", ".cache",
})

# Always excluded filenames
_ALWAYS_EXCLUDED = frozenset({".DS_Store"})

# Deduplication window in seconds
_DEDUP_WINDOW = 1.0


class _FSEventsHandler(FileSystemEventHandler):
    """Handles watchdog filesystem events and converts to RawEvents."""

    def __init__(
        self,
        buffer: list[RawEvent],
        buffer_lock: threading.Lock,
        hostname: str,
        excluded_paths: list[str],
        excluded_extensions: frozenset[str],
    ) -> None:
        super().__init__()
        self._buffer = buffer
        self._buffer_lock = buffer_lock
        self._hostname = hostname
        self._excluded_paths = excluded_paths
        self._excluded_extensions = excluded_extensions
        # Deduplication: path -> last_event_time
        self._recent: dict[str, float] = {}
        self._recent_lock = threading.Lock()

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path, "file_create")

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path, "file_modify")

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if not event.is_directory:
            self._handle(event.src_path, "file_delete")

    def on_moved(self, event: FileMovedEvent) -> None:
        if not event.is_directory:
            self._handle(event.dest_path, "file_rename")

    def _handle(self, path: str, event_type: str) -> None:
        """Process a filesystem event after filtering."""
        # Filter excluded filenames
        basename = os.path.basename(path)
        if basename in _ALWAYS_EXCLUDED:
            return

        # Filter excluded extensions
        _, ext = os.path.splitext(basename)
        if ext.lower() in self._excluded_extensions:
            return

        # Filter excluded path patterns (glob matching)
        for pattern in self._excluded_paths:
            if fnmatch.fnmatch(path, pattern):
                return

        # Deduplicate rapid events for the same path within _DEDUP_WINDOW
        now = time.monotonic()
        with self._recent_lock:
            last = self._recent.get(path)
            if last is not None and (now - last) < _DEDUP_WINDOW:
                return
            self._recent[path] = now

            # Evict stale entries periodically
            if len(self._recent) > 5000:
                cutoff = now - _DEDUP_WINDOW * 2
                self._recent = {
                    k: v for k, v in self._recent.items() if v > cutoff
                }

        raw = RawEvent(
            timestamp=datetime.now(UTC),
            source=event_type,
            message=f"{event_type}: {path}",
            fields={
                "file_path": path,
                "event_type": event_type,
                "pid": "0",
                "name": "unknown",
            },
            hostname=self._hostname,
        )

        with self._buffer_lock:
            self._buffer.append(raw)

    def get_recent_paths(self) -> set[str]:
        """Return set of recently seen paths (for dedup with persistence poller)."""
        now = time.monotonic()
        with self._recent_lock:
            return {
                k for k, v in self._recent.items()
                if (now - v) < 15.0  # wider window for poller dedup
            }


class MacOSFSEventsCollector(Collector):
    """Monitors filesystem changes on macOS using FSEvents (via watchdog).

    Watches configurable paths for file create/modify/delete/rename events.
    Events are buffered and drained by the collector thread.
    """

    def __init__(
        self,
        watched_paths: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        excluded_extensions: frozenset[str] | None = None,
    ) -> None:
        self._watched_paths = watched_paths or DEFAULT_WATCHED_PATHS
        self._excluded_paths = excluded_paths or DEFAULT_EXCLUDED_PATHS
        self._excluded_extensions = excluded_extensions or DEFAULT_EXCLUDED_EXTENSIONS
        self._hostname = socket.gethostname()
        self._buffer: list[RawEvent] = []
        self._buffer_lock = threading.Lock()
        self._observer: Observer | None = None
        self._handler: _FSEventsHandler | None = None

    def name(self) -> str:
        return "macos_fsevents"

    def start(self) -> None:
        if self._observer is not None:
            return

        self._handler = _FSEventsHandler(
            buffer=self._buffer,
            buffer_lock=self._buffer_lock,
            hostname=self._hostname,
            excluded_paths=self._excluded_paths,
            excluded_extensions=self._excluded_extensions,
        )

        self._observer = Observer()
        for path in self._watched_paths:
            expanded = os.path.expanduser(path)
            if os.path.isdir(expanded):
                self._observer.schedule(
                    self._handler, expanded, recursive=True
                )
                logger.debug("FSEvents watching: %s", expanded)
            else:
                logger.debug("FSEvents skipping non-existent path: %s", expanded)

        try:
            self._observer.start()
            logger.info(
                "macOS FSEvents collector started (%d paths)",
                len(self._watched_paths),
            )
        except Exception:
            logger.exception("Failed to start FSEvents observer")
            self._observer = None

    def collect(self) -> list[RawEvent]:
        with self._buffer_lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None
            logger.info("macOS FSEvents collector stopped")

    def get_recent_paths(self) -> set[str]:
        """Return recently seen paths for deduplication with persistence poller."""
        if self._handler:
            return self._handler.get_recent_paths()
        return set()
