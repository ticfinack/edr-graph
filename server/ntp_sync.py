"""NTP clock synchronization for accurate cross-device event correlation.

Provides offset measurement and background drift monitoring, shared
between the fleet server and agents.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger("ntp_sync")


def get_ntp_offset(ntp_server: str = "pool.ntp.org", timeout: float = 5.0) -> float:
    """Query an NTP server and return the local clock offset in seconds.

    Returns 0.0 if NTP is unreachable (fail-open: assume clock is correct).
    """
    try:
        import ntplib

        client = ntplib.NTPClient()
        response = client.request(ntp_server, version=3, timeout=timeout)
        return response.offset
    except Exception:
        logger.debug("NTP query to %s failed", ntp_server, exc_info=True)
        return 0.0


class NtpMonitor:
    """Background thread that periodically measures NTP clock offset.

    Attributes:
        current_offset_ms: Latest measured offset in milliseconds.
    """

    def __init__(self, ntp_server: str = "pool.ntp.org", interval: int = 300) -> None:
        self._ntp_server = ntp_server
        self._interval = interval
        self._offset_seconds: float = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ntp-monitor")

    def start(self) -> None:
        """Start the background NTP polling thread."""
        # Take an initial measurement synchronously
        self._offset_seconds = get_ntp_offset(self._ntp_server)
        logger.info(
            "NTP initial offset: %.1fms (server=%s)",
            self._offset_seconds * 1000,
            self._ntp_server,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(timeout=self._interval):
            offset = get_ntp_offset(self._ntp_server)
            with self._lock:
                self._offset_seconds = offset
            logger.debug("NTP offset: %.1fms", offset * 1000)

    @property
    def current_offset_ms(self) -> int:
        """Current clock offset in milliseconds (rounded)."""
        with self._lock:
            return round(self._offset_seconds * 1000)

    def is_drifting(self, threshold_ms: int = 500) -> bool:
        """Return True if the clock offset exceeds the threshold."""
        return abs(self.current_offset_ms) > threshold_ms

    def stop(self) -> None:
        """Stop the background thread."""
        self._stop.set()
        self._thread.join(timeout=5.0)
