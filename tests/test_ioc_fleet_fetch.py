"""Tests for IocDatabase fleet bundle loading and dual-mode fetching."""

from __future__ import annotations

import pytest

from agent.intel.ioc_database import IocDatabase, IocMatch


@pytest.fixture
def ioc_db():
    return IocDatabase(refresh_interval_hours=999)


def _make_bundle(ips=None, domains=None, hashes=None, feed_stats=None, version=1):
    """Helper to build a minimal intel bundle dict."""
    return {
        "version": version,
        "generated_at": "2026-02-25T12:00:00+00:00",
        "feed_stats": feed_stats or {},
        "ips": ips or {},
        "domains": domains or {},
        "hashes": hashes or {},
    }


def _ioc(feed="test", ioc_type="ip", ioc_value="x", description="test", confidence="high"):
    return {"feed_name": feed, "ioc_type": ioc_type, "ioc_value": ioc_value, "description": description, "confidence": confidence}


class TestLoadBundle:
    def test_load_valid_bundle(self, ioc_db):
        bundle = _make_bundle(
            ips={"1.2.3.4": _ioc(feed="feodo", ioc_value="1.2.3.4")},
            domains={"evil.com": _ioc(feed="threatfox", ioc_type="domain", ioc_value="evil.com")},
            hashes={"a" * 64: _ioc(feed="malbazaar", ioc_type="sha256", ioc_value="a" * 64)},
            feed_stats={"feodo_tracker": 1, "threatfox_domains": 1, "malbazaar": 1},
        )
        assert ioc_db._load_bundle(bundle) is True
        assert ioc_db.check_ip("1.2.3.4") is not None
        assert ioc_db.check_domain("evil.com") is not None
        assert ioc_db.check_hash("a" * 64) is not None
        stats = ioc_db.stats()
        assert stats["ip_count"] == 1
        assert stats["domain_count"] == 1
        assert stats["hash_count"] == 1
        assert stats["feeds"]["feodo_tracker"] == 1

    def test_load_empty_bundle(self, ioc_db):
        bundle = _make_bundle()
        assert ioc_db._load_bundle(bundle) is True
        assert ioc_db.stats()["ip_count"] == 0

    def test_rejects_wrong_version(self, ioc_db):
        # _load_bundle doesn't check version (download_from_fleet does)
        # but we test the version guard in download_from_fleet indirectly
        bundle = _make_bundle(version=99)
        # _load_bundle itself doesn't reject on version — it's a parse-only method
        assert ioc_db._load_bundle(bundle) is True

    def test_applies_suppressions(self, ioc_db):
        ioc_db.set_suppressions([
            {"indicator_type": "ip", "pattern": "1.2.3.4"},
            {"indicator_type": "domain", "pattern": "safe.com"},
            {"indicator_type": "hash", "pattern": "deadbeef"},
        ])
        bundle = _make_bundle(
            ips={
                "1.2.3.4": _ioc(ioc_value="1.2.3.4"),
                "5.6.7.8": _ioc(ioc_value="5.6.7.8"),
            },
            domains={
                "evil.com": _ioc(ioc_type="domain", ioc_value="evil.com"),
                "safe.com": _ioc(ioc_type="domain", ioc_value="safe.com"),
            },
            hashes={
                "deadbeef": _ioc(ioc_type="sha256", ioc_value="deadbeef"),
                "cafebabe": _ioc(ioc_type="sha256", ioc_value="cafebabe"),
            },
        )
        assert ioc_db._load_bundle(bundle) is True
        assert ioc_db.check_ip("1.2.3.4") is None  # suppressed
        assert ioc_db.check_ip("5.6.7.8") is not None
        assert ioc_db.check_domain("safe.com") is None  # suppressed
        assert ioc_db.check_domain("evil.com") is not None
        assert ioc_db.check_hash("deadbeef") is None  # suppressed
        assert ioc_db.check_hash("cafebabe") is not None

    def test_applies_exclusion_patterns(self):
        db = IocDatabase(refresh_interval_hours=999, exclusion_patterns=[r"^internal\."])
        bundle = _make_bundle(
            domains={
                "evil.com": _ioc(ioc_type="domain", ioc_value="evil.com"),
                "internal.corp": _ioc(ioc_type="domain", ioc_value="internal.corp"),
            },
        )
        assert db._load_bundle(bundle) is True
        assert db.check_domain("evil.com") is not None
        assert db.check_domain("internal.corp") is None  # excluded

    def test_missing_confidence_defaults_to_high(self, ioc_db):
        bundle = _make_bundle(
            ips={"1.1.1.1": {"feed_name": "test", "ioc_type": "ip", "ioc_value": "1.1.1.1", "description": "x"}},
        )
        assert ioc_db._load_bundle(bundle) is True
        match = ioc_db.check_ip("1.1.1.1")
        assert match is not None
        assert match.confidence == "high"

    def test_updates_last_refresh(self, ioc_db):
        assert ioc_db.stats()["last_refresh"] is None
        bundle = _make_bundle(ips={"1.1.1.1": _ioc()})
        ioc_db._load_bundle(bundle)
        assert ioc_db.stats()["last_refresh"] is not None


class TestRefreshIfStaleFleetMode:
    def test_calls_fleet_when_params_provided(self, ioc_db, monkeypatch):
        called_with = {}

        def fake_fleet(host, port, key):
            called_with.update(host=host, port=port, key=key)
            return True

        monkeypatch.setattr(ioc_db, "download_from_fleet", fake_fleet)
        ioc_db._last_refresh = 0
        ioc_db._refresh_interval = 0  # Force stale
        ioc_db.refresh_if_stale(fleet_host="server1", fleet_http_port=8080, registration_key="key123")
        assert called_with == {"host": "server1", "port": 8080, "key": "key123"}

    def test_falls_back_on_fleet_failure(self, ioc_db, monkeypatch):
        monkeypatch.setattr(ioc_db, "download_from_fleet", lambda *a: False)
        download_called = []
        monkeypatch.setattr(ioc_db, "download_feeds", lambda: download_called.append(True))
        ioc_db._last_refresh = 0
        ioc_db._refresh_interval = 0  # Force stale
        ioc_db.refresh_if_stale(fleet_host="server1", fleet_http_port=8080, registration_key="key123")
        assert len(download_called) == 1

    def test_direct_download_without_fleet_params(self, ioc_db, monkeypatch):
        download_called = []
        monkeypatch.setattr(ioc_db, "download_feeds", lambda: download_called.append(True))
        ioc_db._last_refresh = 0
        ioc_db._refresh_interval = 0  # Force stale
        ioc_db.refresh_if_stale()  # No fleet params — standalone mode
        assert len(download_called) == 1

    def test_skips_when_not_stale(self, ioc_db, monkeypatch):
        download_called = []
        monkeypatch.setattr(ioc_db, "download_feeds", lambda: download_called.append(True))
        # _last_refresh is 0 but set it to recent
        import time
        ioc_db._last_refresh = time.monotonic()
        ioc_db.refresh_if_stale()
        assert len(download_called) == 0

    def test_skips_when_downloading(self, ioc_db, monkeypatch):
        download_called = []
        monkeypatch.setattr(ioc_db, "download_feeds", lambda: download_called.append(True))
        ioc_db._last_refresh = 0
        ioc_db._refresh_interval = 0  # Would be stale, but downloading flag prevents it
        ioc_db._downloading = True
        ioc_db.refresh_if_stale()
        assert len(download_called) == 0


class TestDownloadFromFleetVersionCheck:
    def test_rejects_wrong_version(self, ioc_db, monkeypatch):
        """download_from_fleet validates version == 1 before calling _load_bundle."""
        import gzip
        import json
        import urllib.request

        bad_bundle = json.dumps({"version": 99, "ips": {}, "domains": {}, "hashes": {}}).encode()
        compressed = gzip.compress(bad_bundle)

        class FakeResponse:
            def __init__(self):
                self.headers = {"Content-Encoding": "gzip"}
            def getcode(self):
                return 200
            def read(self):
                return compressed
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResponse())
        result = ioc_db.download_from_fleet("host", 8080, "key")
        assert result is False
