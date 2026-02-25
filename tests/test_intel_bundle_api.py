"""Tests for GET /api/fleet/intel-bundle and feed-manager-stats endpoints."""

from __future__ import annotations

import gzip
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from server.auth import create_token, hash_password, set_jwt_secret
from server.dashboard import app, set_feed_manager, set_neo4j, set_settings, set_settings_db
from server.settings_db import SettingsDB


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
    fm.get_bundle_gzip.return_value = gzip.compress(
        json.dumps({
            "version": 1,
            "generated_at": "2026-02-25T12:00:00+00:00",
            "feed_stats": {"feodo_tracker": 100},
            "ips": {"1.2.3.4": {"feed_name": "feodo_tracker", "ioc_type": "ip", "ioc_value": "1.2.3.4", "description": "test", "confidence": "high"}},
            "domains": {},
            "hashes": {},
        }).encode()
    )
    fm.get_stats.return_value = {
        "last_upstream_refresh": "2026-02-25T12:00:00+00:00",
        "ip_count": 1,
        "domain_count": 0,
        "hash_count": 0,
        "feed_stats": {"feodo_tracker": 100},
        "bundle_size_bytes": 200,
        "ready": True,
    }
    return fm


@pytest.fixture
def reg_key(settings_db):
    """Create a registration key and return it."""
    key = "test-agent-reg-key-abc123"
    settings_db.create_registration_key(
        key=key,
        label="test key",
        created_by="admin",
    )
    return key


@pytest.fixture
def client(settings_db, mock_settings, mock_feed_manager, reg_key):
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


class TestIntelBundleEndpoint:
    def test_returns_gzip_json(self, client, reg_key):
        resp = client.get(
            "/api/fleet/intel-bundle",
            headers={"Authorization": f"Bearer {reg_key}"},
        )
        assert resp.status_code == 200
        # TestClient auto-decompresses gzip, so content is plain JSON
        # but the header should indicate gzip encoding
        assert resp.headers.get("content-encoding") == "gzip"
        bundle = resp.json()
        assert bundle["version"] == 1
        assert "1.2.3.4" in bundle["ips"]

    def test_rejects_missing_auth(self, client):
        resp = client.get("/api/fleet/intel-bundle")
        assert resp.status_code == 401

    def test_rejects_invalid_key(self, client):
        resp = client.get(
            "/api/fleet/intel-bundle",
            headers={"Authorization": "Bearer bad-key-doesnt-exist"},
        )
        assert resp.status_code == 403

    def test_rejects_revoked_key(self, client, settings_db, reg_key):
        settings_db.revoke_registration_key(reg_key, revoked_by="admin")
        resp = client.get(
            "/api/fleet/intel-bundle",
            headers={"Authorization": f"Bearer {reg_key}"},
        )
        assert resp.status_code == 403

    def test_503_when_bundle_empty(self, client, mock_feed_manager, reg_key):
        mock_feed_manager.get_bundle_gzip.return_value = b""
        resp = client.get(
            "/api/fleet/intel-bundle",
            headers={"Authorization": f"Bearer {reg_key}"},
        )
        assert resp.status_code == 503

    def test_503_when_feed_manager_none(self, client, reg_key):
        set_feed_manager(None)
        resp = client.get(
            "/api/fleet/intel-bundle",
            headers={"Authorization": f"Bearer {reg_key}"},
        )
        assert resp.status_code == 503


class TestFeedManagerStatsEndpoint:
    def test_returns_stats(self, client, auth_headers):
        resp = client.get("/api/threat-intel/feed-manager-stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ready"] is True
        assert data["ip_count"] == 1

    def test_returns_disabled_when_none(self, client, auth_headers):
        set_feed_manager(None)
        resp = client.get("/api/threat-intel/feed-manager-stats", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["ready"] is False

    def test_requires_auth(self, client):
        resp = client.get("/api/threat-intel/feed-manager-stats")
        assert resp.status_code == 401
