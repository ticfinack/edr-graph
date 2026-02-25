"""Tests for server/intel/feed_manager.py."""

from __future__ import annotations

import gzip
import json
from unittest.mock import patch

from server.intel.feed_manager import FeedManager


class TestFeedManagerInit:
    def test_bundle_empty_before_download(self):
        fm = FeedManager(refresh_interval_hours=999)
        assert fm.get_bundle_gzip() == b""

    def test_stats_before_download(self):
        fm = FeedManager(refresh_interval_hours=999)
        stats = fm.get_stats()
        assert stats["ip_count"] == 0
        assert stats["domain_count"] == 0
        assert stats["hash_count"] == 0
        assert stats["ready"] is False
        assert stats["last_upstream_refresh"] is None

    def test_stop_before_start_is_safe(self):
        fm = FeedManager(refresh_interval_hours=999)
        fm.stop()  # Should not raise


class TestDownloadAndCache:
    def test_produces_valid_gzip_json(self):
        fm = FeedManager(refresh_interval_hours=999)
        # Pre-populate internal IocDatabase to avoid actual HTTP calls
        from agent.intel.ioc_database import IocMatch

        fm._ioc_db._ips = {
            "1.2.3.4": IocMatch("feodo", "ip", "1.2.3.4", "test C2", "high"),
            "5.6.7.8": IocMatch("ipsum", "ip", "5.6.7.8", "test rep", "medium"),
        }
        fm._ioc_db._domains = {
            "evil.com": IocMatch("threatfox", "domain", "evil.com", "malware", "high"),
        }
        fm._ioc_db._hashes = {
            "a" * 64: IocMatch("malbazaar", "sha256", "a" * 64, "trojan", "high"),
        }
        fm._ioc_db._feed_stats = {"feodo_tracker": 1, "ipsum": 1, "threatfox_domains": 1, "malbazaar": 1}

        # Patch download_feeds to be a no-op (we pre-populated)
        with patch.object(fm._ioc_db, "download_feeds"):
            fm._download_and_cache()

        raw = gzip.decompress(fm.get_bundle_gzip())
        bundle = json.loads(raw)

        assert bundle["version"] == 1
        assert "generated_at" in bundle
        assert "1.2.3.4" in bundle["ips"]
        assert bundle["ips"]["1.2.3.4"]["feed_name"] == "feodo"
        assert bundle["ips"]["1.2.3.4"]["confidence"] == "high"
        assert bundle["domains"]["evil.com"]
        assert "a" * 64 in bundle["hashes"]
        assert bundle["feed_stats"]["feodo_tracker"] == 1

    def test_stats_after_cache(self):
        fm = FeedManager(refresh_interval_hours=999)
        from agent.intel.ioc_database import IocMatch

        fm._ioc_db._ips = {"1.1.1.1": IocMatch("test", "ip", "1.1.1.1", "x", "high")}
        fm._ioc_db._domains = {}
        fm._ioc_db._hashes = {}
        fm._ioc_db._feed_stats = {"test": 1}

        with patch.object(fm._ioc_db, "download_feeds"):
            fm._download_and_cache()

        stats = fm.get_stats()
        assert stats["ip_count"] == 1
        assert stats["domain_count"] == 0
        assert stats["hash_count"] == 0
        assert stats["ready"] is True
        assert stats["last_upstream_refresh"] is not None
        assert stats["bundle_size_bytes"] > 0

    def test_empty_feeds_produces_valid_bundle(self):
        fm = FeedManager(refresh_interval_hours=999)
        fm._ioc_db._ips = {}
        fm._ioc_db._domains = {}
        fm._ioc_db._hashes = {}
        fm._ioc_db._feed_stats = {}

        with patch.object(fm._ioc_db, "download_feeds"):
            fm._download_and_cache()

        raw = gzip.decompress(fm.get_bundle_gzip())
        bundle = json.loads(raw)
        assert bundle["version"] == 1
        assert bundle["ips"] == {}
        assert bundle["domains"] == {}
        assert bundle["hashes"] == {}
