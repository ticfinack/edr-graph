"""Tests for settings API endpoints in server/dashboard.py."""


import pytest
from fastapi.testclient import TestClient

from server.auth import create_token, hash_password, set_jwt_secret
from server.dashboard import app, set_neo4j, set_settings, set_settings_db
from server.settings_db import SettingsDB


@pytest.fixture
def settings_db(tmp_path):
    sdb = SettingsDB(tmp_path / "test_settings.db")
    yield sdb
    sdb.close()


@pytest.fixture
def mock_settings():
    """Minimal mock of ServerSettings for dashboard endpoints."""

    class FakeSettings:
        jwt_secret = "test-secret-key-for-jwt"
        jwt_ttl_hours = 8
        grpc_port = 50051
        http_port = 8080
        neo4j_uri = "bolt://localhost:7687"

    return FakeSettings()


@pytest.fixture
def client(settings_db, mock_settings):
    set_jwt_secret(mock_settings.jwt_secret)
    set_settings(mock_settings)
    set_settings_db(settings_db)
    set_neo4j(None)  # Neo4j not needed for settings endpoints
    # Create a test admin user
    settings_db.create_user("admin", hash_password("password"), role="admin")
    return TestClient(app)


@pytest.fixture
def auth_headers(mock_settings):
    token = create_token("admin", "admin", mock_settings.jwt_secret, ttl_hours=1)
    return {"Authorization": f"Bearer {token}"}


class TestLoginEndpoint:
    def test_login_success(self, client):
        res = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "password"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "token" in data
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_login_wrong_password(self, client):
        res = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        assert res.status_code == 401

    def test_login_unknown_user(self, client):
        res = client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "password"},
        )
        assert res.status_code == 401


class TestUserEndpoints:
    def test_list_users(self, client, auth_headers):
        res = client.get("/api/settings/users", headers=auth_headers)
        assert res.status_code == 200
        users = res.json()
        assert len(users) >= 1
        assert users[0]["username"] == "admin"
        # Should not include password_hash
        assert "password_hash" not in users[0]

    def test_create_user(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "analyst1", "password": "secret", "role": "analyst"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["username"] == "analyst1"
        assert data["role"] == "analyst"

    def test_create_duplicate_user(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "admin", "password": "x"},
            headers=auth_headers,
        )
        assert res.status_code == 409

    def test_update_user_role(self, client, auth_headers, settings_db):
        settings_db.create_user("bob", hash_password("pass"), role="analyst")
        res = client.put(
            "/api/settings/users/bob",
            json={"role": "viewer"},
            headers=auth_headers,
        )
        assert res.status_code == 200

    def test_update_user_password(self, client, auth_headers, settings_db):
        settings_db.create_user("carol", hash_password("old"), role="admin")
        res = client.put(
            "/api/settings/users/carol",
            json={"password": "newpass"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        # Verify new password works
        login = client.post(
            "/api/auth/login",
            json={"username": "carol", "password": "newpass"},
        )
        assert login.status_code == 200

    def test_update_nonexistent_user(self, client, auth_headers):
        res = client.put(
            "/api/settings/users/ghost",
            json={"role": "admin"},
            headers=auth_headers,
        )
        assert res.status_code == 404

    def test_delete_user(self, client, auth_headers, settings_db):
        settings_db.create_user("deleteme", hash_password("x"))
        res = client.delete("/api/settings/users/deleteme", headers=auth_headers)
        assert res.status_code == 200

    def test_delete_self_prevention(self, client, auth_headers):
        res = client.delete("/api/settings/users/admin", headers=auth_headers)
        assert res.status_code == 400
        assert "Cannot delete your own account" in res.json()["detail"]

    def test_delete_nonexistent_user(self, client, auth_headers):
        res = client.delete("/api/settings/users/ghost", headers=auth_headers)
        assert res.status_code == 404

    def test_unauthorized_access(self, client):
        res = client.get("/api/settings/users")
        assert res.status_code == 401


class TestRegistrationKeyEndpoints:
    def test_create_and_list_key(self, client, auth_headers):
        res = client.post(
            "/api/fleet/registration-keys",
            json={"label": "Test Key"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        key_data = res.json()
        assert key_data["label"] == "Test Key"
        assert len(key_data["key"]) == 64

        listing = client.get("/api/fleet/registration-keys", headers=auth_headers)
        assert len(listing.json()) == 1

    def test_revoke_key(self, client, auth_headers):
        create_res = client.post(
            "/api/fleet/registration-keys",
            json={"label": "Revokable"},
            headers=auth_headers,
        )
        key = create_res.json()["key"]
        res = client.post(
            f"/api/fleet/registration-keys/{key}/revoke", headers=auth_headers
        )
        assert res.status_code == 200

    def test_delete_key(self, client, auth_headers):
        create_res = client.post(
            "/api/fleet/registration-keys",
            json={"label": "Deletable"},
            headers=auth_headers,
        )
        key = create_res.json()["key"]
        res = client.delete(
            f"/api/fleet/registration-keys/{key}", headers=auth_headers
        )
        assert res.status_code == 200

    def test_revoke_nonexistent_key(self, client, auth_headers):
        res = client.post(
            "/api/fleet/registration-keys/nonexistent/revoke", headers=auth_headers
        )
        assert res.status_code == 404


class TestServerSettingsEndpoints:
    def test_get_server_settings(self, client, auth_headers):
        res = client.get("/api/settings/server", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert "editable" in data
        assert "read_only" in data
        assert "jwt_ttl_hours" in data["editable"]
        assert data["read_only"]["grpc_port"] == 50051

    def test_update_server_settings(self, client, auth_headers):
        res = client.put(
            "/api/settings/server",
            json={"jwt_ttl_hours": "24", "ntp_server": "time.google.com"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert "jwt_ttl_hours" in res.json()["updated"]
        assert "ntp_server" in res.json()["updated"]

    def test_update_ignores_non_editable(self, client, auth_headers):
        res = client.put(
            "/api/settings/server",
            json={"grpc_port": "9999", "jwt_ttl_hours": "4"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert "grpc_port" not in res.json()["updated"]


class TestAgentDefaultsEndpoints:
    def test_get_agent_defaults(self, client, auth_headers):
        res = client.get("/api/settings/agent-defaults", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["response_mode"] == "learning"
        assert data["analyzer_interval"] == "60.0"

    def test_update_agent_defaults(self, client, auth_headers):
        res = client.put(
            "/api/settings/agent-defaults",
            json={"response_mode": "enforcing", "analyzer_interval": "30.0"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert "response_mode" in res.json()["updated"]

        # Verify the change persisted
        get_res = client.get("/api/settings/agent-defaults", headers=auth_headers)
        assert get_res.json()["response_mode"] == "enforcing"
