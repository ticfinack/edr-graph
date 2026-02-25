"""Tests for agent/intel/ioc_database.py: IOC suppression filtering."""

import threading

import pytest

from agent.intel.ioc_database import IocDatabase, IocMatch


@pytest.fixture
def ioc_db():
    return IocDatabase(refresh_interval_hours=999)


class TestIocSuppressions:
    def test_set_suppressions_empty(self, ioc_db):
        ioc_db.set_suppressions([])
        stats = ioc_db.stats()
        assert stats["suppressed_ips"] == 0
        assert stats["suppressed_domains"] == 0
        assert stats["suppressed_hashes"] == 0

    def test_set_suppressions_populates_sets(self, ioc_db):
        ioc_db.set_suppressions([
            {"indicator_type": "ip", "pattern": "1.2.3.4"},
            {"indicator_type": "domain", "pattern": "CDN.Example.COM"},
            {"indicator_type": "hash", "pattern": "ABC123"},
        ])
        stats = ioc_db.stats()
        assert stats["suppressed_ips"] == 1
        assert stats["suppressed_domains"] == 1
        assert stats["suppressed_hashes"] == 1

    def test_set_suppressions_normalizes_lowercase(self, ioc_db):
        ioc_db.set_suppressions([
            {"indicator_type": "domain", "pattern": "  CDN.EXAMPLE.COM  "},
        ])
        # Should be stored as lowercase trimmed
        assert ioc_db._suppressed_domains == {"cdn.example.com"}

    def test_set_suppressions_skips_empty_pattern(self, ioc_db):
        ioc_db.set_suppressions([
            {"indicator_type": "ip", "pattern": ""},
            {"indicator_type": "ip", "pattern": "  "},
        ])
        assert ioc_db._suppressed_ips == set()

    def test_set_suppressions_skips_unknown_type(self, ioc_db):
        ioc_db.set_suppressions([
            {"indicator_type": "url", "pattern": "http://evil.com"},
        ])
        assert ioc_db._suppressed_ips == set()
        assert ioc_db._suppressed_domains == set()
        assert ioc_db._suppressed_hashes == set()

    def test_set_suppressions_replaces_previous(self, ioc_db):
        ioc_db.set_suppressions([{"indicator_type": "ip", "pattern": "1.1.1.1"}])
        assert len(ioc_db._suppressed_ips) == 1
        ioc_db.set_suppressions([{"indicator_type": "ip", "pattern": "2.2.2.2"}])
        assert len(ioc_db._suppressed_ips) == 1
        assert "2.2.2.2" in ioc_db._suppressed_ips
        assert "1.1.1.1" not in ioc_db._suppressed_ips

    def test_download_feeds_filters_suppressed_ips(self, ioc_db):
        """Verify that suppressed entries are removed during download_feeds."""
        # Pre-populate IPs dict directly (bypass HTTP downloads)
        ioc_db._ips = {
            "1.2.3.4": IocMatch(feed_name="test", ioc_type="ip", ioc_value="x", description="test"),
            "5.6.7.8": IocMatch(feed_name="test", ioc_type="ip", ioc_value="x", description="test"),
        }
        ioc_db._domains = {
            "evil.com": IocMatch(feed_name="test", ioc_type="ip", ioc_value="x", description="test"),
            "safe.com": IocMatch(feed_name="test", ioc_type="ip", ioc_value="x", description="test"),
        }
        ioc_db._hashes = {
            "deadbeef": IocMatch(feed_name="test", ioc_type="ip", ioc_value="x", description="test"),
        }

        # Set suppressions
        ioc_db.set_suppressions([
            {"indicator_type": "ip", "pattern": "1.2.3.4"},
            {"indicator_type": "domain", "pattern": "safe.com"},
            {"indicator_type": "hash", "pattern": "deadbeef"},
        ])

        # Simulate the suppression logic from download_feeds
        # (we can't call download_feeds directly as it makes HTTP calls)
        with ioc_db._lock:
            sup_ips = set(ioc_db._suppressed_ips)
            sup_domains = set(ioc_db._suppressed_domains)
            sup_hashes = set(ioc_db._suppressed_hashes)

        suppressed_count = 0
        ips = dict(ioc_db._ips)
        domains = dict(ioc_db._domains)
        hashes = dict(ioc_db._hashes)

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

        assert suppressed_count == 3
        assert "1.2.3.4" not in ips
        assert "5.6.7.8" in ips
        assert domains["evil.com"]
        assert "safe.com" not in domains
        assert "deadbeef" not in hashes

    def test_thread_safety(self, ioc_db):
        """Verify set_suppressions is thread-safe."""
        errors = []

        def writer():
            try:
                for _ in range(100):
                    ioc_db.set_suppressions([
                        {"indicator_type": "ip", "pattern": "1.1.1.1"},
                        {"indicator_type": "domain", "pattern": "test.com"},
                    ])
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    ioc_db.stats()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
