"""IP discovery utilities for fleet reporting.

Discovers local interface IPs and periodically resolves the host's public
(NAT) IP via external services.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import urllib.request

import psutil

logger = logging.getLogger("agent.fleet.ip")


_local_ips_cache: list[str] = []
_local_ips_cache_time: float = 0.0
_LOCAL_IPS_TTL: float = 30.0  # seconds


def get_local_ips() -> list[str]:
    """Return all non-loopback, non-link-local IPs from local interfaces.

    IPv4 addresses are sorted before IPv6.  Duplicates are removed.
    Results are cached for 30 seconds to avoid repeated syscalls on every
    heartbeat.
    """
    global _local_ips_cache, _local_ips_cache_time  # noqa: PLW0603

    now = time.monotonic()
    if _local_ips_cache and (now - _local_ips_cache_time) < _LOCAL_IPS_TTL:
        return _local_ips_cache

    ipv4: list[str] = []
    ipv6: list[str] = []

    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                if ip not in ipv4:
                    ipv4.append(ip)
            elif addr.family == socket.AF_INET6:
                ip = addr.address.split("%")[0]  # strip zone id
                if ip == "::1" or ip.startswith("fe80:"):
                    continue
                if ip not in ipv6:
                    ipv6.append(ip)

    result = ipv4 + ipv6
    _local_ips_cache = result
    _local_ips_cache_time = now
    return result


_PUBLIC_IP_URLS = [
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
]


def _fetch_public_ip(timeout: float = 5.0) -> str:
    """Try each public-IP service in order; return first success or ''.

    Falls back silently between providers. If all fail, returns empty string
    and the caller (PublicIpMonitor) keeps the previous value.
    """
    for url in _PUBLIC_IP_URLS:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode().strip()
        except Exception:
            logger.debug("Public IP fetch failed for %s", url, exc_info=True)
            continue
    return ""


class PublicIpMonitor:
    """Daemon thread that periodically resolves the host's public IP."""

    def __init__(self, interval: float = 300.0) -> None:
        self._interval = interval
        self._lock = threading.Lock()
        self._current_ip = ""
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="public-ip-monitor", daemon=True
        )

    @property
    def current_ip(self) -> str:
        with self._lock:
            return self._current_ip

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        # Fetch immediately on start, then every interval
        while not self._stop.is_set():
            ip = _fetch_public_ip()
            if ip:
                with self._lock:
                    if ip != self._current_ip:
                        logger.info("Public IP: %s", ip)
                    self._current_ip = ip
            else:
                with self._lock:
                    prev = self._current_ip
                logger.debug("Public IP fetch failed, keeping previous: %s", prev)
            self._stop.wait(self._interval)
