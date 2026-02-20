"""macOS DNS collector: captures DNS queries via tcpdump on port 53."""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import threading
from datetime import datetime

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)

# Parse tcpdump DNS output lines:
#   21:24:57.638868 IP 10.199.0.7.59833 > 10.199.0.1.53: 30632+ A? httpbin.org. (29)
#   21:24:57.747086 IP 10.199.0.1.53 > 10.199.0.7.59833: 30632 6/0/0 A 35.174.219.145, ... (125)
_QUERY_RE = re.compile(
    r"IP (?P<src>[\d.]+)\.(?P<sport>\d+) > (?P<dst>[\d.]+)\.53: "
    r"\d+\+?\s+(?P<qtype>A|AAAA|CNAME|MX|TXT|PTR|SRV|SOA|NS)\?\s+(?P<domain>\S+)\."
)
_RESPONSE_RE = re.compile(
    r"IP [\d.]+\.53 > [\d.]+\.\d+: "
    r"\d+\s+\d+/\d+/\d+\s+(?P<answers>.+?)\s+\(\d+\)"
)
_IP_IN_ANSWER = re.compile(r"A\s+([\d.]+)")


class MacOSDnsCollector(Collector):
    """Captures DNS queries on macOS using tcpdump on port 53.

    Requires root privileges (tcpdump needs BPF access).
    """

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._buffer: list[RawEvent] = []
        self._buffer_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        # Track recent queries to pair with responses
        self._pending_queries: dict[str, str] = {}  # src:port -> domain

    def name(self) -> str:
        return "macos_dns"

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run_tcpdump, daemon=True, name="macos_dns")
        self._thread.start()

    def _run_tcpdump(self) -> None:
        """Run tcpdump to capture DNS traffic on port 53."""
        try:
            self._proc = subprocess.Popen(
                ["tcpdump", "-i", "any", "-n", "-l", "udp port 53"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            logger.info("macOS DNS collector started (tcpdump on port 53)")

            for line in self._proc.stdout:
                line = line.strip()
                if not line:
                    continue
                self._parse_line(line)

        except FileNotFoundError:
            logger.warning("tcpdump not found — DNS collection disabled")
        except PermissionError:
            logger.warning("tcpdump requires root — DNS collection disabled")
        except OSError as e:
            logger.debug("DNS collector error: %s", e)

    def _parse_line(self, line: str) -> None:
        """Parse a tcpdump output line into a DNS event."""
        # Try to match a DNS query
        m = _QUERY_RE.search(line)
        if m:
            domain = m.group("domain").rstrip(".")
            src_key = f"{m.group('src')}:{m.group('sport')}"
            self._pending_queries[src_key] = domain

            event = RawEvent(
                timestamp=datetime.now(),
                source="unified_log_dns",
                message=f"DNS query: {domain}",
                fields={
                    "query_domain": domain,
                    "query_type": m.group("qtype"),
                    "resolved_ips": "",
                    "name": "mDNSResponder",
                    "pid": "0",
                },
                hostname=self._hostname,
            )
            with self._buffer_lock:
                self._buffer.append(event)
            return

        # Try to match a DNS response (to extract resolved IPs)
        m = _RESPONSE_RE.search(line)
        if m:
            answers = m.group("answers")
            ips = _IP_IN_ANSWER.findall(answers)
            if ips:
                # Find the most recent pending query to associate
                # (simplified — in practice we'd match by transaction ID)
                # Update the last emitted event with resolved IPs
                with self._buffer_lock:
                    if self._buffer:
                        last = self._buffer[-1]
                        if last.source == "unified_log_dns" and not last.fields.get("resolved_ips"):
                            last.fields["resolved_ips"] = ",".join(ips)

        # Limit pending query tracking
        if len(self._pending_queries) > 1000:
            # Evict oldest half
            keys = list(self._pending_queries.keys())
            for k in keys[:500]:
                del self._pending_queries[k]

    def collect(self) -> list[RawEvent]:
        with self._buffer_lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None
