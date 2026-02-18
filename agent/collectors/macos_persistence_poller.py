"""macOS LaunchAgent/LaunchDaemon directory poller.

Belt-and-suspenders approach: if FSEvents misses a rapid create+modify
(coalescing window can swallow it), this poller catches it by periodically
snapshotting persistence directories and diffing against the previous snapshot.

Parses .plist files to extract structured data (Label, ProgramArguments,
RunAtLoad, etc.) which gives the LLM analyzer rich context about what
the LaunchAgent/Daemon actually does.
"""

from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .base import Collector, RawEvent

if sys.platform != "darwin":
    raise ImportError("Persistence poller is macOS-only")

logger = logging.getLogger(__name__)

PERSISTENCE_DIRS = [
    os.path.expanduser("~/Library/LaunchAgents/"),
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/Library/StartupItems/",
]


@dataclass
class FileSnapshot:
    mtime: float
    sha256: str
    size: int


def _hash_file(path: str) -> str | None:
    """Compute SHA256 of a file. Returns None on failure."""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def parse_launch_plist(path: str) -> dict | None:
    """Parse a LaunchAgent/Daemon plist and extract key fields.

    Returns structured data valuable for LLM reasoning about what
    the agent/daemon actually does.
    """
    try:
        with open(path, "rb") as f:
            plist = plistlib.load(f)
        return {
            "label": plist.get("Label"),
            "program": plist.get("Program"),
            "program_arguments": plist.get("ProgramArguments"),
            "run_at_load": plist.get("RunAtLoad", False),
            "keep_alive": plist.get("KeepAlive", False),
            "watch_paths": plist.get("WatchPaths"),
            "start_interval": plist.get("StartInterval"),
        }
    except Exception:
        return None


class MacOSPersistencePoller(Collector):
    """Polls LaunchAgent/LaunchDaemon directories for new/modified/deleted plists.

    On each poll cycle:
    1. Snapshot each directory: {filename: (mtime, sha256, size)}
    2. Diff against previous snapshot
    3. Emit file_create/file_modify/file_delete events for changes
    4. Parse new/modified plist files and include structured data in event raw fields

    Deduplicates against FSEvents collector: if FSEvents already reported the
    same path within the last poll interval, the poller skips it.
    """

    def __init__(
        self,
        directories: list[str] | None = None,
        poll_interval: float = 10.0,
        fsevents_collector=None,
    ) -> None:
        self._directories = directories or PERSISTENCE_DIRS
        self._poll_interval = poll_interval
        self._fsevents_collector = fsevents_collector
        self._hostname = socket.gethostname()
        self._buffer: list[RawEvent] = []
        self._buffer_lock = threading.Lock()
        self._snapshots: dict[str, dict[str, FileSnapshot]] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def name(self) -> str:
        return "macos_persistence_poller"

    def start(self) -> None:
        if self._thread is not None:
            return

        # Take initial snapshot
        for d in self._directories:
            expanded = os.path.expanduser(d)
            if os.path.isdir(expanded):
                self._snapshots[expanded] = self._snapshot_dir(expanded)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="persistence_poller"
        )
        self._thread.start()
        logger.info(
            "macOS persistence poller started (%d dirs, %.0fs interval)",
            len(self._directories),
            self._poll_interval,
        )

    def _poll_loop(self) -> None:
        """Main polling loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break

            try:
                self._poll_cycle()
            except Exception:
                logger.exception("Persistence poller cycle failed")

    def _poll_cycle(self) -> None:
        """Single poll cycle: snapshot, diff, emit events."""
        # Get recently seen paths from FSEvents for deduplication
        fsevents_recent: set[str] = set()
        if self._fsevents_collector is not None:
            try:
                fsevents_recent = self._fsevents_collector.get_recent_paths()
            except Exception:
                pass

        for d in self._directories:
            expanded = os.path.expanduser(d)
            if not os.path.isdir(expanded):
                continue

            new_snapshot = self._snapshot_dir(expanded)
            old_snapshot = self._snapshots.get(expanded, {})

            # Detect new files
            for fname, snap in new_snapshot.items():
                fpath = os.path.join(expanded, fname)

                # Skip if FSEvents already reported this path
                if fpath in fsevents_recent:
                    continue

                if fname not in old_snapshot:
                    # New file
                    plist_data = None
                    if fname.endswith(".plist"):
                        plist_data = parse_launch_plist(fpath)

                    fields = {
                        "file_path": fpath,
                        "event_type": "file_create",
                        "pid": "0",
                        "name": "unknown",
                        "sha256": snap.sha256,
                        "file_size": str(snap.size),
                    }
                    if plist_data:
                        for k, v in plist_data.items():
                            if v is not None:
                                fields[f"plist_{k}"] = str(v)

                    self._emit("file_create", fpath, fields)

                elif (
                    snap.mtime != old_snapshot[fname].mtime
                    or snap.sha256 != old_snapshot[fname].sha256
                ):
                    # Modified file
                    plist_data = None
                    if fname.endswith(".plist"):
                        plist_data = parse_launch_plist(fpath)

                    fields = {
                        "file_path": fpath,
                        "event_type": "file_modify",
                        "pid": "0",
                        "name": "unknown",
                        "sha256": snap.sha256,
                        "old_sha256": old_snapshot[fname].sha256,
                        "file_size": str(snap.size),
                    }
                    if plist_data:
                        for k, v in plist_data.items():
                            if v is not None:
                                fields[f"plist_{k}"] = str(v)

                    self._emit("file_modify", fpath, fields)

            # Detect deleted files
            for fname in old_snapshot:
                if fname not in new_snapshot:
                    fpath = os.path.join(expanded, fname)
                    if fpath in fsevents_recent:
                        continue
                    self._emit(
                        "file_delete",
                        fpath,
                        {
                            "file_path": fpath,
                            "event_type": "file_delete",
                            "pid": "0",
                            "name": "unknown",
                        },
                    )

            self._snapshots[expanded] = new_snapshot

    def _snapshot_dir(self, directory: str) -> dict[str, FileSnapshot]:
        """Take a snapshot of all files in a directory."""
        snapshot: dict[str, FileSnapshot] = {}
        try:
            for entry in os.scandir(directory):
                if not entry.is_file():
                    continue
                try:
                    stat = entry.stat()
                    file_hash = _hash_file(entry.path) or ""
                    snapshot[entry.name] = FileSnapshot(
                        mtime=stat.st_mtime,
                        sha256=file_hash,
                        size=stat.st_size,
                    )
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            logger.debug("Cannot read directory: %s", directory)
        return snapshot

    def _emit(self, event_type: str, path: str, fields: dict) -> None:
        """Create and buffer a RawEvent."""
        raw = RawEvent(
            timestamp=datetime.now(timezone.utc),
            source=event_type,
            message=f"{event_type}: {path}",
            fields=fields,
            hostname=self._hostname,
        )
        with self._buffer_lock:
            self._buffer.append(raw)

    def collect(self) -> list[RawEvent]:
        with self._buffer_lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("macOS persistence poller stopped")
