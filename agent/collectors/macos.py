"""macOS-specific collector: unified log, /var/log."""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)


class MacOSCollector(Collector):
    """Collects events from macOS unified log and /var/log."""

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._log_buffer: list[RawEvent] = []
        self._buffer_lock = threading.Lock()
        self._stream_proc: subprocess.Popen | None = None
        self._stream_thread: threading.Thread | None = None
        self._file_positions: dict[str, int] = {}
        self._log_files = [
            "/var/log/system.log",
            "/var/log/install.log",
        ]

    def name(self) -> str:
        return "macos"

    def start(self) -> None:
        """Start the unified log stream in a background thread."""
        if self._stream_thread is not None:
            return
        self._stream_thread = threading.Thread(
            target=self._run_log_stream, daemon=True
        )
        self._stream_thread.start()

    def _run_log_stream(self) -> None:
        """Run `log stream` and buffer events."""
        try:
            predicate = (
                '(eventType == "logEvent") AND ('
                'subsystem == "com.apple.authd" OR '
                'subsystem == "com.apple.securityd" OR '
                'subsystem == "com.apple.opendirectoryd" OR '
                'category == "process" OR '
                'category == "network" OR '
                'category == "security"'
                ')'
            )
            self._stream_proc = subprocess.Popen(
                [
                    "log", "stream", "--style", "ndjson",
                    "--predicate", predicate,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in self._stream_proc.stdout:
                line = line.strip()
                if not line or line.startswith("Filtering"):
                    continue
                try:
                    entry = json.loads(line)
                    image_path = entry.get("processImagePath", "")
                    proc_name = Path(image_path).name if image_path else ""
                    pid = entry.get("processID", 0)
                    event = RawEvent(
                        timestamp=datetime.now(),
                        source="unified_log",
                        message=entry.get("eventMessage", ""),
                        fields={
                            "name": proc_name,
                            "process": image_path,
                            "pid": str(pid),
                            "subsystem": entry.get("subsystem", ""),
                            "category": entry.get("category", ""),
                        },
                        hostname=self._hostname,
                    )
                    with self._buffer_lock:
                        self._log_buffer.append(event)
                except json.JSONDecodeError:
                    continue
        except (FileNotFoundError, OSError) as e:
            logger.debug("Cannot start log stream: %s", e)

    def collect(self) -> list[RawEvent]:
        events: list[RawEvent] = []

        # Drain the log stream buffer
        with self._buffer_lock:
            events.extend(self._log_buffer)
            self._log_buffer.clear()

        # Tail var/log files
        for log_file in self._log_files:
            events.extend(self._tail_file(log_file))

        return events

    def _tail_file(self, path: str) -> list[RawEvent]:
        """Read new lines from a log file since last position."""
        events: list[RawEvent] = []
        log_path = Path(path)
        if not log_path.exists():
            return events

        try:
            pos = self._file_positions.get(path, 0)
            with open(log_path) as f:
                if pos == 0:
                    f.seek(0, 2)
                    self._file_positions[path] = f.tell()
                    return events

                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    events.append(
                        RawEvent(
                            timestamp=datetime.now(),
                            source="macos_log",
                            message=line,
                            fields={},
                            hostname=self._hostname,
                        )
                    )
                self._file_positions[path] = f.tell()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", path, e)

        return events

    def stop(self) -> None:
        if self._stream_proc:
            self._stream_proc.terminate()
            self._stream_proc = None
