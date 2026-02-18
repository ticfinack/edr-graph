"""IOC feed database — downloads and caches known-bad indicators from abuse.ch.

Feeds (all free, no API key required):
- Feodo Tracker: botnet C2 IPs (Dridex, Emotet, TrickBot, QakBot)
- ThreatFox: recent IOCs (IPs, domains, URLs) from various malware families
- URLhaus: active malware distribution URLs (domain extraction)
- MalBazaar: recent malware SHA256 hashes
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 30  # seconds — feeds can be large


@dataclass
class IocMatch:
    """Represents a match against a known-bad indicator."""

    feed_name: str  # "feodo_tracker", "threatfox", "urlhaus", "malbazaar"
    ioc_type: str  # "ip", "domain", "sha256", "url"
    ioc_value: str
    description: str
    confidence: str = "high"


class IocDatabase:
    """Thread-safe database of known-bad indicators from abuse.ch feeds.

    Call :meth:`download_feeds` once at startup, then use :meth:`check_ip`,
    :meth:`check_domain`, and :meth:`check_hash` from any thread.
    """

    def __init__(self, refresh_interval_hours: float = 4.0) -> None:
        self._ips: dict[str, IocMatch] = {}
        self._domains: dict[str, IocMatch] = {}
        self._hashes: dict[str, IocMatch] = {}
        self._last_refresh: float = 0.0
        self._refresh_interval: float = refresh_interval_hours * 3600
        self._lock = threading.Lock()

    # -- Public API --------------------------------------------------------

    def download_feeds(self) -> None:
        """Download all feeds (blocking). Safe to call from any thread."""
        with self._lock:
            ips: dict[str, IocMatch] = {}
            domains: dict[str, IocMatch] = {}
            hashes: dict[str, IocMatch] = {}

            self._download_feodo(ips)
            self._download_threatfox(ips, domains)
            self._download_urlhaus(domains)
            self._download_malbazaar(hashes)

            self._ips = ips
            self._domains = domains
            self._hashes = hashes
            self._last_refresh = time.monotonic()

            logger.info(
                "Downloaded %d IPs, %d domains, %d hashes from IOC feeds",
                len(self._ips),
                len(self._domains),
                len(self._hashes),
            )

    def refresh_if_stale(self) -> None:
        """Refresh feeds if the refresh interval has elapsed."""
        if time.monotonic() - self._last_refresh > self._refresh_interval:
            logger.info("Refreshing IOC feeds...")
            self.download_feeds()

    def check_ip(self, ip: str) -> IocMatch | None:
        """Check an IP against all feeds. Thread-safe."""
        with self._lock:
            return self._ips.get(ip)

    def check_domain(self, domain: str) -> IocMatch | None:
        """Check a domain against all feeds. Thread-safe."""
        with self._lock:
            return self._domains.get(domain.lower())

    def check_hash(self, sha256: str) -> IocMatch | None:
        """Check a SHA256 hash against all feeds. Thread-safe."""
        with self._lock:
            return self._hashes.get(sha256.lower())

    def stats(self) -> dict:
        """Return feed database statistics."""
        with self._lock:
            last_refresh_iso = None
            if self._last_refresh > 0:
                # Convert monotonic offset to wall-clock time
                elapsed = time.monotonic() - self._last_refresh
                wall = datetime.now(timezone.utc).timestamp() - elapsed
                last_refresh_iso = datetime.fromtimestamp(
                    wall, tz=timezone.utc
                ).isoformat()

            return {
                "ip_count": len(self._ips),
                "domain_count": len(self._domains),
                "hash_count": len(self._hashes),
                "last_refresh": last_refresh_iso,
                "refresh_interval_hours": self._refresh_interval / 3600,
            }

    # -- Feed downloaders --------------------------------------------------

    @staticmethod
    def _http_get(url: str) -> str:
        """Download a URL, return body text."""
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "edr-graph-agent/1.0"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def _download_feodo(self, ips: dict[str, IocMatch]) -> None:
        """Feodo Tracker — botnet C2 IP blocklist."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
        try:
            body = self._http_get(url)
            count = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips[line] = IocMatch(
                    feed_name="feodo_tracker",
                    ioc_type="ip",
                    ioc_value=line,
                    description="Feodo Tracker botnet C2",
                )
                count += 1
            logger.debug("Feodo Tracker: %d IPs", count)
        except Exception:
            logger.warning("Failed to download Feodo Tracker feed", exc_info=True)

    def _download_threatfox(
        self,
        ips: dict[str, IocMatch],
        domains: dict[str, IocMatch],
    ) -> None:
        """ThreatFox — recent IOCs (JSON export)."""
        url = "https://threatfox.abuse.ch/export/json/recent/"
        try:
            body = self._http_get(url)
            data = json.loads(body)

            # ThreatFox JSON: {"query_status": "ok", "data": [{"id":..., "ioc":"...", "ioc_type":"...", ...}, ...]}
            # But the actual format wraps entries by ID: {"query_status":"ok", "data": {"0": [{...}], "1": [{...}], ...}}
            entries = data.get("data")
            if not entries:
                return

            count_ip = 0
            count_domain = 0

            # Handle both list-of-dicts and dict-of-lists formats
            items: list[dict] = []
            if isinstance(entries, dict):
                for entry_list in entries.values():
                    if isinstance(entry_list, list):
                        items.extend(entry_list)
                    elif isinstance(entry_list, dict):
                        items.append(entry_list)
            elif isinstance(entries, list):
                items = entries

            for item in items:
                ioc_value = item.get("ioc", "")
                ioc_type = item.get("ioc_type", "")
                malware = item.get("malware_printable", "")
                threat_type = item.get("threat_type", "")

                desc = f"ThreatFox: {malware}" if malware else f"ThreatFox: {threat_type}"

                if ioc_type == "ip:port":
                    # Extract just the IP from "1.2.3.4:443"
                    ip = ioc_value.split(":")[0].strip()
                    if ip and ip not in ips:
                        ips[ip] = IocMatch(
                            feed_name="threatfox",
                            ioc_type="ip",
                            ioc_value=ip,
                            description=desc,
                        )
                        count_ip += 1
                elif ioc_type == "domain":
                    domain = ioc_value.strip().lower()
                    if domain and domain not in domains:
                        domains[domain] = IocMatch(
                            feed_name="threatfox",
                            ioc_type="domain",
                            ioc_value=domain,
                            description=desc,
                        )
                        count_domain += 1
                elif ioc_type == "url":
                    # Extract domain from URL
                    try:
                        parsed = urlparse(ioc_value if "://" in ioc_value else f"http://{ioc_value}")
                        domain = (parsed.hostname or "").lower()
                        if domain and domain not in domains:
                            domains[domain] = IocMatch(
                                feed_name="threatfox",
                                ioc_type="domain",
                                ioc_value=domain,
                                description=desc,
                            )
                            count_domain += 1
                    except Exception:
                        pass

            logger.debug("ThreatFox: %d IPs, %d domains", count_ip, count_domain)
        except Exception:
            logger.warning("Failed to download ThreatFox feed", exc_info=True)

    def _download_urlhaus(self, domains: dict[str, IocMatch]) -> None:
        """URLhaus — active malware distribution URLs (extract domains)."""
        url = "https://urlhaus.abuse.ch/downloads/text_online/"
        try:
            body = self._http_get(url)
            count = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    parsed = urlparse(line if "://" in line else f"http://{line}")
                    domain = (parsed.hostname or "").lower()
                    if domain and domain not in domains:
                        domains[domain] = IocMatch(
                            feed_name="urlhaus",
                            ioc_type="domain",
                            ioc_value=domain,
                            description="URLhaus active malware distribution",
                        )
                        count += 1
                except Exception:
                    pass
            logger.debug("URLhaus: %d domains", count)
        except Exception:
            logger.warning("Failed to download URLhaus feed", exc_info=True)

    def _download_malbazaar(self, hashes: dict[str, IocMatch]) -> None:
        """MalBazaar — recent malware SHA256 hashes."""
        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        try:
            body = self._http_get(url)
            count = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # SHA256 hashes are 64 hex chars
                if len(line) == 64:
                    hashes[line.lower()] = IocMatch(
                        feed_name="malbazaar",
                        ioc_type="sha256",
                        ioc_value=line.lower(),
                        description="MalBazaar recent malware sample",
                    )
                    count += 1
            logger.debug("MalBazaar: %d hashes", count)
        except Exception:
            logger.warning("Failed to download MalBazaar feed", exc_info=True)
