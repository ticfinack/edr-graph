"""Linux auditd collector via netlink socket.

Receives real-time audit events from the kernel's audit subsystem over a
``AF_NETLINK`` / ``NETLINK_AUDIT`` socket.  Falls back to the ``python-audit``
library if available, or raw netlink message parsing otherwise.

Requires root or ``CAP_AUDIT_READ`` capability.
"""

from __future__ import annotations

import collections
import logging
import re
import socket
import struct
import threading
from datetime import datetime

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)

_BUFFER_MAX = 10_000

# Linux netlink constants
AF_NETLINK = 16
NETLINK_AUDIT = 9

# Audit message types we care about
AUDIT_SYSCALL = 1300
AUDIT_EXECVE = 1309

# Netlink message header: length(u32), type(u16), flags(u16), seq(u32), pid(u32)
_NLMSG_HDR = struct.Struct("=IHHII")  # 16 bytes

# Key audit rules to install
_AUDIT_RULES = [
    "-a always,exit -F arch=b64 -S execve",
    "-a always,exit -F arch=b64 -S connect",
    "-w /etc/passwd -p wa",
    "-w /etc/shadow -p wa",
    "-w /etc/sudoers -p wa",
]


class AuditdCollector(Collector):
    """Real-time Linux audit event collector via netlink.

    Architecture:
    - ``start()`` opens a netlink socket and spawns a consumer thread
    - Events are buffered in a bounded ``collections.deque`` with a lock
    - ``collect()`` drains the deque (called by collector thread every ~5s)
    - ``stop()`` closes the socket and stops the consumer thread
    """

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._buffer: collections.deque[RawEvent] = collections.deque(maxlen=_BUFFER_MAX)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None

    def name(self) -> str:
        return "auditd"

    def start(self) -> None:
        """Open netlink socket and spawn consumer thread."""
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._consume, daemon=True, name="auditd-consumer"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the consumer to stop and close the socket."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._thread = None

    def collect(self) -> list[RawEvent]:
        """Drain buffered audit events."""
        events: list[RawEvent] = []
        with self._lock:
            while self._buffer:
                events.append(self._buffer.popleft())
        return events

    def _consume(self) -> None:
        """Read audit events from netlink socket."""
        try:
            self._sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
            self._sock.bind((0, 0))
            self._sock.settimeout(1.0)

            self._configure_audit_rules()

            while not self._stop_event.is_set():
                try:
                    data = self._sock.recv(8192)
                    if not data:
                        continue
                    self._parse_netlink_messages(data)
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
        except PermissionError:
            logger.warning(
                "Auditd collector requires root or CAP_AUDIT_READ — disabled"
            )
        except OSError as e:
            logger.debug("Auditd netlink error: %s", e)
        except Exception:
            logger.debug("Auditd consumer error", exc_info=True)

    def _configure_audit_rules(self) -> None:
        """Attempt to install audit rules (best-effort, may require auditctl)."""
        import subprocess

        for rule in _AUDIT_RULES:
            try:
                subprocess.run(
                    ["auditctl"] + rule.split(),
                    capture_output=True,
                    timeout=5,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                logger.debug("Could not install audit rule: %s", rule)
                break

    def _parse_netlink_messages(self, data: bytes) -> None:
        """Parse netlink message header(s) and extract audit events."""
        offset = 0
        while offset < len(data):
            if offset + _NLMSG_HDR.size > len(data):
                break
            msg_len, msg_type, flags, seq, pid = _NLMSG_HDR.unpack_from(data, offset)
            if msg_len < _NLMSG_HDR.size or offset + msg_len > len(data):
                break

            payload = data[offset + _NLMSG_HDR.size: offset + msg_len]
            self._handle_audit_message(msg_type, payload)

            # Align to 4-byte boundary
            offset += (msg_len + 3) & ~3

    def _handle_audit_message(self, msg_type: int, payload: bytes) -> None:
        """Convert an audit payload into a RawEvent."""
        try:
            text = payload.decode("utf-8", errors="replace").strip("\x00").strip()
        except Exception:
            return

        if not text:
            return

        fields = _parse_audit_kv(text)

        if msg_type == AUDIT_EXECVE:
            source = "auditd_execve"
        elif msg_type == AUDIT_SYSCALL:
            source = "auditd_syscall"
        else:
            source = "auditd_syscall"

        raw = RawEvent(
            timestamp=datetime.now(),
            source=source,
            message=text,
            fields=fields,
            hostname=self._hostname,
        )
        with self._lock:
            self._buffer.append(raw)


def _parse_audit_kv(text: str) -> dict[str, str]:
    """Parse audit key=value pairs from a message payload."""
    fields: dict[str, str] = {}
    for match in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', text):
        key, value = match.group(1), match.group(2)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value

    # Map to common field names
    if "pid" not in fields and "a0" in fields:
        fields["pid"] = fields.get("pid", "0")
    if "exe" in fields:
        fields["name"] = fields["exe"].rsplit("/", 1)[-1]
    if "comm" in fields and "name" not in fields:
        fields["name"] = fields["comm"]
    return fields
