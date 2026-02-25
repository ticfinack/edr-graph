"""Centralized threat intel feed aggregator for the fleet server.

Downloads OSINT feeds on a configurable interval and caches the
aggregated IOC bundle in memory as gzipped JSON for serving to agents.
"""

from __future__ import annotations

import gzip
import json
import logging
import threading
import time
from datetime import UTC, datetime

from agent.intel.ioc_database import IocDatabase, IocMatch

logger = logging.getLogger("server.intel")


class FeedManager:
    """Background thread that downloads OSINT feeds and caches a gzipped JSON bundle.

    The bundle is an atomic snapshot: agents either get the full previous
    bundle or the full new bundle, never a partial state.

    Lifecycle: call start() to begin the background thread, stop() to shut down.
    start() is non-blocking — the first download happens in the background thread.
    """

    def __init__(self, refresh_interval_hours: float = 4.0) -> None:
        self._ioc_db = IocDatabase(refresh_interval_hours=refresh_interval_hours)
        self._refresh_interval = refresh_interval_hours * 3600
        self._bundle_bytes: bytes = b""
        self._bundle_json: dict = {}
        self._last_upstream_refresh: str = ""
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="feed-manager",
        )

    def start(self) -> None:
        """Start the background feed download thread (non-blocking).

        The first download happens in the background — the bundle will be
        empty until it completes. Callers should check get_bundle_gzip()
        and return 503 if empty.
        """
        self._thread.start()
        logger.info(
            "Feed manager started (refresh=%.1fh, initial download in background)",
            self._refresh_interval / 3600,
        )

    def _run(self) -> None:
        # Initial download immediately
        try:
            self._download_and_cache()
        except Exception:
            logger.warning("Feed manager initial download failed", exc_info=True)
        # Then periodic refresh
        while not self._stop.wait(timeout=self._refresh_interval):
            try:
                self._download_and_cache()
            except Exception:
                logger.warning("Feed manager download cycle failed", exc_info=True)

    def _download_and_cache(self) -> None:
        """Download all feeds, build the bundle, compress it."""
        logger.info("Downloading upstream OSINT feeds...")
        t0 = time.monotonic()
        self._ioc_db.download_feeds()

        # Snapshot internal dicts under IocDatabase's lock
        with self._ioc_db._lock:
            ips_snapshot = dict(self._ioc_db._ips)
            domains_snapshot = dict(self._ioc_db._domains)
            hashes_snapshot = dict(self._ioc_db._hashes)
            feed_stats = dict(self._ioc_db._feed_stats)

        now_iso = datetime.now(UTC).isoformat()

        bundle: dict = {
            "version": 1,
            "generated_at": now_iso,
            "feed_stats": feed_stats,
            "ips": {
                k: _match_to_dict(v) for k, v in ips_snapshot.items()
            },
            "domains": {
                k: _match_to_dict(v) for k, v in domains_snapshot.items()
            },
            "hashes": {
                k: _match_to_dict(v) for k, v in hashes_snapshot.items()
            },
        }

        raw_json = json.dumps(bundle, separators=(",", ":"))
        compressed = gzip.compress(raw_json.encode("utf-8"), compresslevel=6)
        elapsed = time.monotonic() - t0

        with self._lock:
            self._bundle_bytes = compressed
            self._bundle_json = bundle
            self._last_upstream_refresh = now_iso

        logger.info(
            "Intel bundle cached: %d IPs, %d domains, %d hashes "
            "(%.1f KB compressed, %.1fs elapsed)",
            len(ips_snapshot),
            len(domains_snapshot),
            len(hashes_snapshot),
            len(compressed) / 1024,
            elapsed,
        )

    def get_bundle_gzip(self) -> bytes:
        """Return the current gzipped bundle bytes. Thread-safe.

        Returns empty bytes if the initial download has not completed yet.
        """
        with self._lock:
            return self._bundle_bytes

    def get_stats(self) -> dict:
        """Return feed manager statistics for the dashboard."""
        with self._lock:
            bundle = self._bundle_json
            last_refresh = self._last_upstream_refresh
            bundle_size = len(self._bundle_bytes)
        return {
            "last_upstream_refresh": last_refresh or None,
            "ip_count": len(bundle.get("ips", {})),
            "domain_count": len(bundle.get("domains", {})),
            "hash_count": len(bundle.get("hashes", {})),
            "feed_stats": bundle.get("feed_stats", {}),
            "bundle_size_bytes": bundle_size,
            "ready": bundle_size > 0,
        }

    def get_paginated_indicators(
        self,
        ioc_type: str = "ip",
        page: int = 1,
        limit: int = 100,
        query: str = "",
        feed: str = "",
    ) -> dict:
        """Return a paginated, filterable slice of the cached indicator bundle.

        Grabs a stable reference to _bundle_json under the lock,
        then filters/slices outside the lock (the dict is atomically swapped).
        """
        section_map = {"ip": "ips", "domain": "domains", "hash": "hashes"}
        section = section_map.get(ioc_type, "ips")

        with self._lock:
            bundle = self._bundle_json

        entries = bundle.get(section, {})
        q = query.lower() if query else ""
        feed_lower = feed.lower() if feed else ""

        filtered: list[dict] = []
        for key, meta in entries.items():
            if q and q not in key.lower():
                continue
            if feed_lower and meta.get("feed_name", "").lower() != feed_lower:
                continue
            filtered.append({
                "indicator": key,
                "type": ioc_type,
                "feed_name": meta.get("feed_name", ""),
                "description": meta.get("description", ""),
                "confidence": meta.get("confidence", ""),
            })

        total = len(filtered)
        pages = max(1, (total + limit - 1) // limit)
        page = max(1, min(page, pages))
        start = (page - 1) * limit
        items = filtered[start : start + limit]

        return {"items": items, "total": total, "page": page, "pages": pages}

    def stop(self) -> None:
        """Stop the background thread."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10.0)


def _match_to_dict(m: IocMatch) -> dict:
    """Serialize an IocMatch dataclass to a JSON-safe dict."""
    return {
        "feed_name": m.feed_name,
        "ioc_type": m.ioc_type,
        "ioc_value": m.ioc_value,
        "description": m.description,
        "confidence": m.confidence,
    }
