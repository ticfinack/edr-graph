"""Linux-specific collectors: journald, auditd, syslog, auth.log."""

from __future__ import annotations

import logging
import re
import socket
from datetime import datetime
from pathlib import Path

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)


class LinuxCollector(Collector):
    """Collects events from Linux-specific log sources."""

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._file_positions: dict[str, int] = {}
        self._log_files = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/auth.log",
        ]

    def name(self) -> str:
        return "linux"

    def collect(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        for log_file in self._log_files:
            events.extend(self._tail_file(log_file))
        events.extend(self._read_audit_log())
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
                # On first read, seek to end
                if pos == 0:
                    f.seek(0, 2)
                    self._file_positions[path] = f.tell()
                    return events

                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    source = "auth" if "auth" in path else "syslog"
                    events.append(
                        RawEvent(
                            timestamp=datetime.now(),
                            source=source,
                            message=line,
                            fields=self._parse_syslog_line(line),
                            hostname=self._hostname,
                        )
                    )
                self._file_positions[path] = f.tell()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read %s: %s", path, e)

        return events

    def _read_audit_log(self) -> list[RawEvent]:
        """Read new entries from auditd log."""
        audit_path = "/var/log/audit/audit.log"
        events: list[RawEvent] = []
        if not Path(audit_path).exists():
            return events

        try:
            pos = self._file_positions.get(audit_path, 0)
            with open(audit_path) as f:
                if pos == 0:
                    f.seek(0, 2)
                    self._file_positions[audit_path] = f.tell()
                    return events

                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    fields = self._parse_audit_line(line)
                    events.append(
                        RawEvent(
                            timestamp=datetime.now(),
                            source="auditd",
                            message=line,
                            fields=fields,
                            hostname=self._hostname,
                        )
                    )
                self._file_positions[audit_path] = f.tell()
        except (PermissionError, OSError) as e:
            logger.debug("Cannot read audit log: %s", e)

        return events

    @staticmethod
    def _parse_syslog_line(line: str) -> dict[str, str]:
        """Parse basic syslog fields."""
        fields: dict[str, str] = {}
        # Match: Jan 15 10:30:45 hostname process[pid]: message
        match = re.match(
            r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)",
            line,
        )
        if match:
            fields["log_time"] = match.group(1)
            fields["log_host"] = match.group(2)
            fields["program"] = match.group(3)
            if match.group(4):
                fields["pid"] = match.group(4)
            fields["log_message"] = match.group(5)
        return fields

    @staticmethod
    def _parse_audit_line(line: str) -> dict[str, str]:
        """Parse auditd key=value fields."""
        fields: dict[str, str] = {}
        type_match = re.search(r"type=(\S+)", line)
        if type_match:
            fields["audit_type"] = type_match.group(1)
        for match in re.finditer(r"(\w+)=(?:"([^"]*)"|([\S]+))", line):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            fields[key] = value
        return fields
