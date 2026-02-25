"""Tests for the Active OSINT Explorer (paginated indicator browsing)."""

from __future__ import annotations

import math
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.auth import create_token, hash_password, set_jwt_secret
from server.dashboard import app, set_feed_manager, set_neo4j, set_settings, set_settings_db
from server.intel.feed_manager import FeedManager
from server.settings_db import SettingsDB


# ── FeedManager.get_paginated_indicators() unit tests ──


class TestGetPaginatedIndicators:
    """Unit tests for FeedManager.get_paginated_indicators()."""

    def _make_fm(self):
        """Create a FeedManager with pre-populated test data (no download)."""
        from agent.intel.ioc_database import IocMatch

        fm = FeedManager(refresh_interval_hours=999)
        fm._ioc_db._ips = {
            "1.2.3.4": IocMatch("feodo", "ip", "1.2.3.4", "C2 server", "high"),
            "10.0.0.1": IocMatch("ipsum", "ip", "10.0.0.1", "scanner", "medium"),
            "192.168.1.100": IocMatch("ipsum", "ip", "192.168.1.100", "internal test", "low"),
            "5.6.7.8": IocMatch("feodo", "ip", "5.6.7.8", "C2 #2", "high"),
            "8.8.8.8": IocMatch("blocklist_de", "ip", "8.8.8.8", "dns", "low"),
        }
        fm._ioc_db._domains = {
            "evil.com": IocMatch("threatfox", "domain", "evil.com", "malware C2", "high"),
            "bad-example.org": IocMatch("threatfox", "domain", "bad-example.org", "phishing", "medium"),
        }
        fm._ioc_db._hashes = {
            "a" * 64: IocMatch("malbazaar", "sha256", "a" * 64, "trojan", "high"),
            "b" * 64: IocMatch("malbazaar", "sha256", "b" * 64, "ransomware", "high"),
        }
        fm._ioc_db._feed_stats = {"feodo": 2, "ipsum": 2, "blocklist_de": 1, "threatfox": 2, "malbazaar": 2}
        with patch.object(fm._ioc_db, "download_feeds"):
            fm._download_and_cache()
        return fm

    def test_returns_all_ips_page1(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip")
        assert result["total"] == 5
        assert result["page"] == 1
        assert result["pages"] == 1
        assert len(result["items"]) == 5
        assert all(r["type"] == "ip" for r in result["items"])

    def test_returns_domains(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="domain")
        assert result["total"] == 2
        assert len(result["items"]) == 2
        assert all(r["type"] == "domain" for r in result["items"])

    def test_returns_hashes(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="hash")
        assert result["total"] == 2
        assert all(r["type"] == "hash" for r in result["items"])

    def test_pagination(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", limit=2, page=1)
        assert result["total"] == 5
        assert result["pages"] == 3  # ceil(5/2)
        assert result["page"] == 1
        assert len(result["items"]) == 2

        result2 = fm.get_paginated_indicators(ioc_type="ip", limit=2, page=3)
        assert result2["page"] == 3
        assert len(result2["items"]) == 1  # last page has remainder

    def test_page_clamped_to_max(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", page=999)
        assert result["page"] == 1  # only 1 page, so clamped

    def test_page_clamped_to_min(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", page=0)
        assert result["page"] == 1

    def test_filter_by_query(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", query="192")
        assert result["total"] == 1
        assert result["items"][0]["indicator"] == "192.168.1.100"

    def test_filter_by_feed(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", feed="feodo")
        assert result["total"] == 2
        assert all(r["feed_name"] == "feodo" for r in result["items"])

    def test_filter_by_query_and_feed(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", query="1.2", feed="feodo")
        assert result["total"] == 1
        assert result["items"][0]["indicator"] == "1.2.3.4"

    def test_filter_case_insensitive(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="domain", query="EVIL")
        assert result["total"] == 1
        assert result["items"][0]["indicator"] == "evil.com"

    def test_feed_filter_case_insensitive(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", feed="FEODO")
        assert result["total"] == 2

    def test_no_results(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="ip", query="zzz-no-match")
        assert result["total"] == 0
        assert result["items"] == []
        assert result["pages"] == 1

    def test_empty_bundle(self):
        fm = FeedManager(refresh_interval_hours=999)
        result = fm.get_paginated_indicators()
        assert result["total"] == 0
        assert result["items"] == []

    def test_result_fields(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="domain", query="evil.com")
        assert len(result["items"]) == 1
        r = result["items"][0]
        assert r["indicator"] == "evil.com"
        assert r["type"] == "domain"
        assert r["feed_name"] == "threatfox"
        assert r["description"] == "malware C2"
        assert r["confidence"] == "high"

    def test_type_maps_to_suppression_vocabulary(self):
        """Verify types are 'ip', 'domain', 'hash' — matching suppression API."""
        fm = self._make_fm()
        for ioc_type in ("ip", "domain", "hash"):
            result = fm.get_paginated_indicators(ioc_type=ioc_type)
            assert all(r["type"] == ioc_type for r in result["items"])

    def test_invalid_type_defaults_to_ips(self):
        fm = self._make_fm()
        result = fm.get_paginated_indicators(ioc_type="invalid")
        # Falls back to "ips" section which has 5 entries
        assert result["total"] == 5


# ── Dashboard endpoint tests ──


@pytest.fixture
def settings_db(tmp_path):
    sdb = SettingsDB(tmp_path / "test_settings.db")
    yield sdb
    sdb.close()


@pytest.fixture
def mock_settings():
    class FakeSettings:
        jwt_secret = "test-secret-key-for-jwt"
        jwt_ttl_hours = 8

    return FakeSettings()


@pytest.fixture
def mock_feed_manager():
    fm = MagicMock()
    fm.get_paginated_indicators.return_value = {
        "items": [
            {"indicator": "1.2.3.4", "type": "ip", "feed_name": "feodo", "description": "C2", "confidence": "high"},
            {"indicator": "5.6.7.8", "type": "ip", "feed_name": "ipsum", "description": "scan", "confidence": "medium"},
        ],
        "total": 47000,
        "page": 1,
        "pages": 470,
    }
    return fm


@pytest.fixture
def client(settings_db, mock_settings, mock_feed_manager):
    set_jwt_secret(mock_settings.jwt_secret)
    set_settings(mock_settings)
    set_settings_db(settings_db)
    set_neo4j(None)
    set_feed_manager(mock_feed_manager)
    settings_db.create_user("admin", hash_password("password"), role="admin")
    return TestClient(app)


@pytest.fixture
def auth_headers(mock_settings):
    token = create_token("admin", "admin", mock_settings.jwt_secret, ttl_hours=1)
    return {"Authorization": f"Bearer {token}"}


class TestIndicatorsEndpoint:
    def test_default_returns_ips_page1(self, client, auth_headers, mock_feed_manager):
        resp = client.get("/api/threat-intel/indicators", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "pages" in data
        mock_feed_manager.get_paginated_indicators.assert_called_once_with(
            ioc_type="ip", page=1, limit=100, query="", feed="",
        )

    def test_passes_query_params(self, client, auth_headers, mock_feed_manager):
        resp = client.get(
            "/api/threat-intel/indicators?type=domain&page=3&limit=50&q=evil&feed=threatfox",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        mock_feed_manager.get_paginated_indicators.assert_called_once_with(
            ioc_type="domain", page=3, limit=50, query="evil", feed="threatfox",
        )

    def test_requires_auth(self, client):
        resp = client.get("/api/threat-intel/indicators")
        assert resp.status_code == 401

    def test_rejects_invalid_type(self, client, auth_headers):
        resp = client.get("/api/threat-intel/indicators?type=malware", headers=auth_headers)
        assert resp.status_code == 422

    def test_rejects_invalid_page(self, client, auth_headers):
        resp = client.get("/api/threat-intel/indicators?page=0", headers=auth_headers)
        assert resp.status_code == 422

    def test_rejects_invalid_limit(self, client, auth_headers):
        resp = client.get("/api/threat-intel/indicators?limit=999", headers=auth_headers)
        assert resp.status_code == 422

    def test_returns_empty_when_no_feed_manager(self, client, auth_headers):
        set_feed_manager(None)
        resp = client.get("/api/threat-intel/indicators", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["pages"] == 1
