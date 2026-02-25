"""IOC feed database — downloads and caches known-bad indicators.

Feeds (all free, no API key required):

IP feeds:
- Feodo Tracker (aggressive): historical botnet C2 IPs
- Stamparm ipsum: aggregated IP reputation (seen on 3+ blacklists)
- Blocklist.de: attack source IPs from honeypots/IDS
- C2 Tracker (montysecurity): active C2 framework IPs (Cobalt Strike, etc.)
- Emerging Threats: compromised IPs

Domain/IOC feeds:
- ThreatFox: recent IOCs (IPs, domains, URLs) from various malware families
- URLhaus: active malware distribution URLs (domain extraction)

Hash feeds:
- MalBazaar: recent malware SHA256 hashes
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 45  # seconds — some feeds are large
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Legitimate infrastructure domains that host user-uploaded malware.
# URLhaus/ThreatFox list URLs on these services, but the domains themselves
# are not malicious — blocking them would break normal operations.
_DOMAIN_ALLOWLIST = frozenset(
    {
        # Cloud storage / CDN
        "storage.googleapis.com",
        "firebasestorage.googleapis.com",
        "drive.google.com",
        "docs.google.com",
        "sites.google.com",
        "s3.amazonaws.com",
        "blob.core.windows.net",
        "1drv.ms",
        "onedrive.live.com",
        # Code hosting
        "github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "gist.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        # File sharing / paste
        "dropbox.com",
        "dl.dropboxusercontent.com",
        "pastebin.com",
        "paste.ee",
        "transfer.sh",
        "cdn.discordapp.com",
        "media.discordapp.net",
        "discord.gg",
        "anonfiles.com",
        "mega.nz",
        "mediafire.com",
        # Web hosting / archives
        "web.archive.org",
        "archive.org",
        "img1.wsimg.com",
        "wordpress.com",
        "blogspot.com",
        "weebly.com",
        # URL shorteners
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "rebrand.ly",
    }
)


@dataclass
class IocMatch:
    """Represents a match against a known-bad indicator."""

    feed_name: str
    ioc_type: str  # "ip", "domain", "sha256", "url"
    ioc_value: str
    description: str
    confidence: str = "high"


class IocDatabase:
    """Thread-safe database of known-bad indicators from public threat feeds.

    Call :meth:`download_feeds` once at startup, then use :meth:`check_ip`,
    :meth:`check_domain`, and :meth:`check_hash` from any thread.
    """

    def __init__(
        self,
        refresh_interval_hours: float = 4.0,
        exclusion_patterns: list[str] | None = None,
    ) -> None:
        self._ips: dict[str, IocMatch] = {}
        self._domains: dict[str, IocMatch] = {}
        self._hashes: dict[str, IocMatch] = {}
        self._last_refresh: float = 0.0
        self._refresh_interval: float = refresh_interval_hours * 3600
        self._lock = threading.Lock()
        # Progress fields — written by download thread, read by dashboard.
        # Protected by _progress_lock (separate from _lock to avoid contention
        # with the lookup-dict lock during long downloads).
        self._progress_lock = threading.Lock()
        self._downloading = False
        self._download_progress: str = ""  # Current feed being downloaded
        self._feeds_done: int = 0  # Number of feeds completed so far
        self._feeds_total: int = 0  # Computed at download start
        self._feed_stats: dict[str, int] = {}
        # Fleet-managed suppressions (false positive filter)
        self._suppressed_ips: set[str] = set()
        self._suppressed_domains: set[str] = set()
        self._suppressed_hashes: set[str] = set()
        # User-configurable regex exclusions for domains/IPs
        self._exclusion_patterns: list[re.Pattern] = []
        for pat in exclusion_patterns or []:
            try:
                self._exclusion_patterns.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                logger.warning("Invalid IOC exclusion pattern: %s", pat)

    def _is_excluded(self, value: str) -> bool:
        """Check if a value matches any user-configured exclusion pattern."""
        return any(p.search(value) for p in self._exclusion_patterns)

    def set_suppressions(self, suppressions: list[dict]) -> None:
        """Accept fleet-pushed suppression list. Thread-safe."""
        ip_set: set[str] = set()
        domain_set: set[str] = set()
        hash_set: set[str] = set()
        for s in suppressions:
            t = s.get("indicator_type", "")
            p = s.get("pattern", "").strip().lower()
            if not p:
                continue
            if t == "ip":
                ip_set.add(p)
            elif t == "domain":
                domain_set.add(p)
            elif t == "hash":
                hash_set.add(p)
        with self._lock:
            self._suppressed_ips = ip_set
            self._suppressed_domains = domain_set
            self._suppressed_hashes = hash_set
        logger.info(
            "Updated suppressions: %d IPs, %d domains, %d hashes",
            len(ip_set), len(domain_set), len(hash_set),
        )

    # -- Public API --------------------------------------------------------

    def download_feeds(self) -> None:
        """Download all feeds (blocking). Safe to call from any thread.

        Downloads are performed without holding the lock so that
        check_ip/check_domain/stats calls are not blocked during the
        (potentially slow) HTTP fetches. The lock is only held for the
        final atomic swap of the lookup dicts.
        """
        with self._progress_lock:
            self._downloading = True
            self._feeds_done = 0
            self._feeds_total = 8  # 5 IP + ThreatFox + URLhaus + MalBazaar
        ips: dict[str, IocMatch] = {}
        domains: dict[str, IocMatch] = {}
        hashes: dict[str, IocMatch] = {}
        stats: dict[str, int] = {}

        def _track(name, fn, *args):
            with self._progress_lock:
                self._download_progress = name
            result = fn(*args)
            with self._progress_lock:
                self._feeds_done += 1
            return result

        # IP feeds
        stats["feodo_tracker"] = _track("Feodo Tracker", self._download_feodo, ips)
        stats["ipsum"] = _track("IPsum", self._download_ipsum, ips)
        stats["blocklist_de"] = _track("Blocklist.de", self._download_blocklist_de, ips)
        stats["c2_tracker"] = _track("C2 Tracker", self._download_c2_tracker, ips)
        stats["emerging_threats"] = _track("Emerging Threats", self._download_emerging_threats, ips)

        # Domain/IOC feeds
        with self._progress_lock:
            self._download_progress = "ThreatFox"
        tf_ip, tf_dom = self._download_threatfox(ips, domains)
        with self._progress_lock:
            self._feeds_done += 1
        stats["threatfox_ips"] = tf_ip
        stats["threatfox_domains"] = tf_dom
        stats["urlhaus"] = _track("URLhaus", self._download_urlhaus, domains)

        # Hash feeds
        stats["malbazaar"] = _track("MalBazaar", self._download_malbazaar, hashes)

        # Apply fleet-managed suppressions before loading into enforcement engine
        with self._lock:
            sup_ips = set(self._suppressed_ips)
            sup_domains = set(self._suppressed_domains)
            sup_hashes = set(self._suppressed_hashes)

        suppressed_count = 0
        for ip in sup_ips:
            if ip in ips:
                del ips[ip]
                suppressed_count += 1
        for domain in sup_domains:
            if domain in domains:
                del domains[domain]
                suppressed_count += 1
        for h in sup_hashes:
            if h in hashes:
                del hashes[h]
                suppressed_count += 1

        if suppressed_count:
            logger.info("Suppressed %d IOC entries via fleet rules", suppressed_count)

        # Atomic swap under lock
        with self._lock:
            self._ips = ips
            self._domains = domains
            self._hashes = hashes
            self._feed_stats = stats
            self._last_refresh = time.monotonic()
        with self._progress_lock:
            self._downloading = False

        logger.info(
            "IOC feeds loaded: %d IPs, %d domains, %d hashes "
            "(feodo=%d ipsum=%d blocklist_de=%d c2_tracker=%d et=%d "
            "threatfox=%d+%d urlhaus=%d malbazaar=%d)",
            len(ips),
            len(domains),
            len(hashes),
            stats.get("feodo_tracker", 0),
            stats.get("ipsum", 0),
            stats.get("blocklist_de", 0),
            stats.get("c2_tracker", 0),
            stats.get("emerging_threats", 0),
            stats.get("threatfox_ips", 0),
            stats.get("threatfox_domains", 0),
            stats.get("urlhaus", 0),
            stats.get("malbazaar", 0),
        )

    def refresh_if_stale(
        self,
        fleet_host: str = "",
        fleet_http_port: int = 0,
        registration_key: str = "",
    ) -> None:
        """Refresh feeds if the refresh interval has elapsed.

        If fleet parameters are provided, attempts to fetch the pre-built
        intel bundle from the fleet server first.  Falls back to direct
        OSINT download on any failure (including HTTP 503 during fleet
        server startup).
        """
        with self._progress_lock:
            downloading = self._downloading
        if downloading:
            return
        if time.monotonic() - self._last_refresh > self._refresh_interval:
            if fleet_host and fleet_http_port and registration_key:
                logger.info("Refreshing IOC feeds from fleet server...")
                if self.download_from_fleet(fleet_host, fleet_http_port, registration_key):
                    return
                logger.info("Fleet fetch failed, falling back to direct OSINT download")
            logger.info("Refreshing IOC feeds...")
            self.download_feeds()

    def download_from_fleet(
        self,
        fleet_host: str,
        fleet_http_port: int,
        registration_key: str,
    ) -> bool:
        """Fetch the pre-built IOC bundle from the fleet server.

        Returns True on success, False on any failure so the caller can
        fall back to direct OSINT download.
        """
        url = f"http://{fleet_host}:{fleet_http_port}/api/fleet/intel-bundle"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "edr-graph-agent/1.0",
                    "Authorization": f"Bearer {registration_key}",
                    "Accept-Encoding": "gzip",
                },
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                status = resp.getcode()
                if status != 200:
                    logger.warning("Fleet intel-bundle returned HTTP %d", status)
                    return False
                raw = resp.read()
                encoding = resp.headers.get("Content-Encoding", "")
                if encoding == "gzip":
                    raw = gzip.decompress(raw)
                bundle = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 503:
                logger.info(
                    "Fleet intel compiling (503), falling back to direct download"
                )
            else:
                logger.warning(
                    "Failed to fetch intel bundle from fleet (%s): HTTP %d",
                    url, e.code,
                )
            return False
        except Exception:
            logger.warning(
                "Failed to fetch intel bundle from fleet (%s)", url, exc_info=True,
            )
            return False

        if not isinstance(bundle, dict) or bundle.get("version") != 1:
            logger.warning("Invalid intel bundle format from fleet")
            return False

        return self._load_bundle(bundle)

    def _load_bundle(self, bundle: dict) -> bool:
        """Parse a fleet intel bundle dict into internal lookup dicts.

        Applies local exclusion patterns and fleet suppressions before
        the atomic swap — identical filtering to ``download_feeds()``.
        Returns True on success.
        """
        try:
            ips: dict[str, IocMatch] = {}
            for key, val in bundle.get("ips", {}).items():
                ips[key] = IocMatch(
                    feed_name=val["feed_name"],
                    ioc_type=val["ioc_type"],
                    ioc_value=val["ioc_value"],
                    description=val["description"],
                    confidence=val.get("confidence", "high"),
                )

            domains: dict[str, IocMatch] = {}
            for key, val in bundle.get("domains", {}).items():
                if not self._is_excluded(key):
                    domains[key] = IocMatch(
                        feed_name=val["feed_name"],
                        ioc_type=val["ioc_type"],
                        ioc_value=val["ioc_value"],
                        description=val["description"],
                        confidence=val.get("confidence", "high"),
                    )

            hashes: dict[str, IocMatch] = {}
            for key, val in bundle.get("hashes", {}).items():
                hashes[key] = IocMatch(
                    feed_name=val["feed_name"],
                    ioc_type=val["ioc_type"],
                    ioc_value=val["ioc_value"],
                    description=val["description"],
                    confidence=val.get("confidence", "high"),
                )

            # Apply fleet-managed suppressions (same path as download_feeds)
            with self._lock:
                sup_ips = set(self._suppressed_ips)
                sup_domains = set(self._suppressed_domains)
                sup_hashes = set(self._suppressed_hashes)

            suppressed_count = 0
            for ip in sup_ips:
                if ip in ips:
                    del ips[ip]
                    suppressed_count += 1
            for domain in sup_domains:
                if domain in domains:
                    del domains[domain]
                    suppressed_count += 1
            for h in sup_hashes:
                if h in hashes:
                    del hashes[h]
                    suppressed_count += 1

            if suppressed_count:
                logger.info("Suppressed %d IOC entries via fleet rules", suppressed_count)

            stats = bundle.get("feed_stats", {})

            # Atomic swap
            with self._lock:
                self._ips = ips
                self._domains = domains
                self._hashes = hashes
                self._feed_stats = stats
                self._last_refresh = time.monotonic()

            logger.info(
                "Loaded intel bundle from fleet: %d IPs, %d domains, %d hashes",
                len(ips), len(domains), len(hashes),
            )
            return True

        except Exception:
            logger.warning("Failed to parse intel bundle from fleet", exc_info=True)
            return False

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
        with self._progress_lock:
            downloading = self._downloading
            progress = self._download_progress
            feeds_done = self._feeds_done
            feeds_total = self._feeds_total

        with self._lock:
            last_refresh_iso = None
            if self._last_refresh > 0:
                elapsed = time.monotonic() - self._last_refresh
                wall = datetime.now(UTC).timestamp() - elapsed
                last_refresh_iso = datetime.fromtimestamp(wall, tz=UTC).isoformat()

            result = {
                "ip_count": len(self._ips),
                "domain_count": len(self._domains),
                "hash_count": len(self._hashes),
                "last_refresh": last_refresh_iso,
                "refresh_interval_hours": self._refresh_interval / 3600,
                "feeds": dict(self._feed_stats),
                "exclusion_patterns": len(self._exclusion_patterns),
                "downloading": downloading,
                "suppressed_ips": len(self._suppressed_ips),
                "suppressed_domains": len(self._suppressed_domains),
                "suppressed_hashes": len(self._suppressed_hashes),
            }
            if downloading:
                result["download_progress"] = progress
                result["feeds_done"] = feeds_done
                result["feeds_total"] = feeds_total
            return result

    # -- HTTP helper -------------------------------------------------------

    @staticmethod
    def _http_get(url: str) -> str:
        """Download a URL, return body text.

        Prefers curl (handles CDN/HTTP2 reliably) with urllib as fallback.
        Python 3.14's urllib can stall on some CDN hosts (e.g.
        raw.githubusercontent.com via Fastly) where curl works instantly.
        """
        if shutil.which("curl"):
            result = subprocess.run(
                ["curl", "-sfL", "--max-time", str(_HTTP_TIMEOUT),
                 "-A", "edr-graph-agent/1.0", url],
                capture_output=True, timeout=_HTTP_TIMEOUT + 5,
            )
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace")
            # Non-zero exit — fall through to urllib
            logger.debug("curl failed for %s (rc=%d), trying urllib", url, result.returncode)
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "edr-graph-agent/1.0"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")

    @staticmethod
    def _parse_ip_lines(body: str) -> list[str]:
        """Extract valid IPs from a text body, skipping comments/blanks."""
        ips = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            # Some feeds have "ip\tscore" format
            ip = line.split()[0].strip()
            if _IP_RE.match(ip):
                ips.append(ip)
        return ips

    # -- Feed downloaders --------------------------------------------------

    def _download_feodo(self, ips: dict[str, IocMatch]) -> int:
        """Feodo Tracker aggressive — all historical botnet C2 IPs."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
        try:
            body = self._http_get(url)
            count = 0
            for ip in self._parse_ip_lines(body):
                if ip not in ips:
                    ips[ip] = IocMatch(
                        feed_name="feodo_tracker",
                        ioc_type="ip",
                        ioc_value=ip,
                        description="Feodo Tracker botnet C2",
                    )
                    count += 1
            logger.debug("Feodo Tracker: %d IPs", count)
            return count
        except Exception:
            logger.warning("Failed to download Feodo Tracker feed", exc_info=True)
            return 0

    def _download_ipsum(self, ips: dict[str, IocMatch]) -> int:
        """Stamparm ipsum — aggregated IP reputation (score >= 3 blacklists)."""
        url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
        try:
            body = self._http_get(url)
            count = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, score_str = parts[0], parts[1]
                try:
                    score = int(score_str)
                except ValueError:
                    continue
                # Only include IPs seen on 3+ blacklists for quality
                if score < 3 or not _IP_RE.match(ip):
                    continue
                if ip not in ips:
                    confidence = "high" if score >= 5 else "medium"
                    ips[ip] = IocMatch(
                        feed_name="ipsum",
                        ioc_type="ip",
                        ioc_value=ip,
                        description=f"ipsum reputation (score {score}/{score_str})",
                        confidence=confidence,
                    )
                    count += 1
            logger.debug("ipsum: %d IPs (score>=3)", count)
            return count
        except Exception:
            logger.warning("Failed to download ipsum feed", exc_info=True)
            return 0

    def _download_blocklist_de(self, ips: dict[str, IocMatch]) -> int:
        """Blocklist.de — attack source IPs from IDS/honeypots."""
        url = "https://lists.blocklist.de/lists/all.txt"
        try:
            body = self._http_get(url)
            count = 0
            for ip in self._parse_ip_lines(body):
                if ip not in ips:
                    ips[ip] = IocMatch(
                        feed_name="blocklist_de",
                        ioc_type="ip",
                        ioc_value=ip,
                        description="Blocklist.de attack source",
                        confidence="medium",
                    )
                    count += 1
            logger.debug("Blocklist.de: %d IPs", count)
            return count
        except Exception:
            logger.warning("Failed to download Blocklist.de feed", exc_info=True)
            return 0

    def _download_c2_tracker(self, ips: dict[str, IocMatch]) -> int:
        """C2 Tracker — active C2 framework IPs (Cobalt Strike, Sliver, etc.)."""
        url = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"
        try:
            body = self._http_get(url)
            count = 0
            for ip in self._parse_ip_lines(body):
                if ip not in ips:
                    ips[ip] = IocMatch(
                        feed_name="c2_tracker",
                        ioc_type="ip",
                        ioc_value=ip,
                        description="C2 Tracker — active C2 framework server",
                    )
                    count += 1
            logger.debug("C2 Tracker: %d IPs", count)
            return count
        except Exception:
            logger.warning("Failed to download C2 Tracker feed", exc_info=True)
            return 0

    def _download_emerging_threats(self, ips: dict[str, IocMatch]) -> int:
        """Emerging Threats — compromised IPs."""
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        try:
            body = self._http_get(url)
            count = 0
            for ip in self._parse_ip_lines(body):
                if ip not in ips:
                    ips[ip] = IocMatch(
                        feed_name="emerging_threats",
                        ioc_type="ip",
                        ioc_value=ip,
                        description="Emerging Threats compromised host",
                        confidence="medium",
                    )
                    count += 1
            logger.debug("Emerging Threats: %d IPs", count)
            return count
        except Exception:
            logger.warning("Failed to download Emerging Threats feed", exc_info=True)
            return 0

    def _download_threatfox(
        self,
        ips: dict[str, IocMatch],
        domains: dict[str, IocMatch],
    ) -> tuple[int, int]:
        """ThreatFox — recent IOCs via CSV export."""
        url = "https://threatfox.abuse.ch/export/csv/recent/"
        try:
            body = self._http_get(url)
            count_ip = 0
            count_domain = 0

            # Skip comment lines
            lines = [line for line in body.splitlines() if line.strip() and not line.startswith("#")]
            reader = csv.reader(io.StringIO("\n".join(lines)))

            for row in reader:
                if len(row) < 6:
                    continue
                # CSV columns: date, id, ioc, ioc_type, threat_type, malware, ...
                ioc_value = row[2].strip().strip('"')
                ioc_type = row[3].strip().strip('"')
                malware = row[7].strip().strip('"') if len(row) > 7 else ""
                desc = f"ThreatFox: {malware}" if malware else "ThreatFox IOC"

                if ioc_type == "ip:port":
                    ip = ioc_value.split(":")[0].strip()
                    if ip and _IP_RE.match(ip) and ip not in ips:
                        ips[ip] = IocMatch(
                            feed_name="threatfox",
                            ioc_type="ip",
                            ioc_value=ip,
                            description=desc,
                        )
                        count_ip += 1
                elif ioc_type == "domain":
                    domain = ioc_value.strip().lower()
                    if (
                        domain
                        and domain not in domains
                        and domain not in _DOMAIN_ALLOWLIST
                        and not self._is_excluded(domain)
                    ):
                        domains[domain] = IocMatch(
                            feed_name="threatfox",
                            ioc_type="domain",
                            ioc_value=domain,
                            description=desc,
                        )
                        count_domain += 1
                elif ioc_type == "url":
                    try:
                        parsed = urlparse(ioc_value if "://" in ioc_value else f"http://{ioc_value}")
                        domain = (parsed.hostname or "").lower()
                        if (
                            domain
                            and domain not in domains
                            and domain not in _DOMAIN_ALLOWLIST
                            and not self._is_excluded(domain)
                        ):
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
            return count_ip, count_domain
        except Exception:
            logger.warning("Failed to download ThreatFox feed", exc_info=True)
            return 0, 0

    def _download_urlhaus(self, domains: dict[str, IocMatch]) -> int:
        """URLhaus — active malware distribution URLs (extract domains)."""
        url = "https://urlhaus.abuse.ch/downloads/text_online/"
        try:
            body = self._http_get(url)
            count = 0
            skipped = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    parsed = urlparse(line if "://" in line else f"http://{line}")
                    domain = (parsed.hostname or "").lower()
                    if not domain or domain in domains:
                        continue
                    if domain in _DOMAIN_ALLOWLIST or self._is_excluded(domain):
                        skipped += 1
                        continue
                    domains[domain] = IocMatch(
                        feed_name="urlhaus",
                        ioc_type="domain",
                        ioc_value=domain,
                        description="URLhaus active malware distribution",
                    )
                    count += 1
                except Exception:
                    pass
            logger.debug("URLhaus: %d domains (%d allowlisted)", count, skipped)
            return count
        except Exception:
            logger.warning("Failed to download URLhaus feed", exc_info=True)
            return 0

    def _download_malbazaar(self, hashes: dict[str, IocMatch]) -> int:
        """MalBazaar — recent malware SHA256 hashes."""
        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        try:
            body = self._http_get(url)
            count = 0
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if len(line) == 64:
                    hashes[line.lower()] = IocMatch(
                        feed_name="malbazaar",
                        ioc_type="sha256",
                        ioc_value=line.lower(),
                        description="MalBazaar recent malware sample",
                    )
                    count += 1
            logger.debug("MalBazaar: %d hashes", count)
            return count
        except Exception:
            logger.warning("Failed to download MalBazaar feed", exc_info=True)
            return 0
