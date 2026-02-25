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


@pytest.fixture
def viewer_headers(mock_settings, settings_db):
    settings_db.create_user("viewer1", hash_password("vpass"), role="viewer")
    token = create_token("viewer1", "viewer", mock_settings.jwt_secret, ttl_hours=1)
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
            json={"username": "analyst1", "password": "secret", "role": "viewer"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["username"] == "analyst1"
        assert data["role"] == "viewer"

    def test_create_duplicate_user(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "admin", "password": "x"},
            headers=auth_headers,
        )
        assert res.status_code == 409

    def test_update_user_role(self, client, auth_headers, settings_db):
        settings_db.create_user("bob", hash_password("pass"), role="viewer")
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

    def test_update_agent_defaults_skips_invalid_keys(self, client, auth_headers):
        res = client.put(
            "/api/settings/agent-defaults",
            json={
                "response_mode": "enforcing",
                "evil_setting": "injected",
                "data_dir": "/etc/shadow",
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert "response_mode" in data["updated"]
        assert "evil_setting" in data["skipped"]
        assert "data_dir" in data["skipped"]

    def test_update_agent_defaults_all_invalid_keys(self, client, auth_headers):
        res = client.put(
            "/api/settings/agent-defaults",
            json={"bad_key": "value"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["updated"] == []
        assert res.json()["skipped"] == ["bad_key"]


class TestRBAC:
    """Viewer role should get 403 on admin-only endpoints, 200 on read endpoints."""

    def test_viewer_can_read_settings(self, client, viewer_headers):
        res = client.get("/api/settings/server", headers=viewer_headers)
        assert res.status_code == 200

    def test_viewer_can_read_agent_defaults(self, client, viewer_headers):
        res = client.get("/api/settings/agent-defaults", headers=viewer_headers)
        assert res.status_code == 200

    def test_viewer_can_read_users(self, client, viewer_headers):
        res = client.get("/api/settings/users", headers=viewer_headers)
        assert res.status_code == 200

    def test_viewer_can_read_tags(self, client, viewer_headers):
        res = client.get("/api/settings/tags", headers=viewer_headers)
        assert res.status_code == 200

    def test_viewer_can_read_registration_keys(self, client, viewer_headers):
        res = client.get("/api/fleet/registration-keys", headers=viewer_headers)
        assert res.status_code == 200

    def test_viewer_cannot_create_user(self, client, viewer_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "hacker", "password": "x"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_update_user(self, client, viewer_headers):
        res = client.put(
            "/api/settings/users/admin",
            json={"role": "viewer"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_delete_user(self, client, viewer_headers):
        res = client.delete("/api/settings/users/admin", headers=viewer_headers)
        assert res.status_code == 403

    def test_viewer_cannot_update_server_settings(self, client, viewer_headers):
        res = client.put(
            "/api/settings/server",
            json={"jwt_ttl_hours": "1"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_update_agent_defaults(self, client, viewer_headers):
        res = client.put(
            "/api/settings/agent-defaults",
            json={"response_mode": "enforcing"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_create_tag(self, client, viewer_headers):
        res = client.post(
            "/api/settings/tags",
            json={"tag_name": "evil"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_delete_tag(self, client, viewer_headers, settings_db):
        settings_db.create_tag("prod")
        res = client.delete("/api/settings/tags/prod", headers=viewer_headers)
        assert res.status_code == 403

    def test_viewer_cannot_set_tag_policy(self, client, viewer_headers, settings_db):
        settings_db.create_tag("prod")
        res = client.put(
            "/api/settings/tags/prod/policy",
            json={"overrides": {"response_mode": "enforcing"}, "rules": []},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_create_registration_key(self, client, viewer_headers):
        res = client.post(
            "/api/fleet/registration-keys",
            json={"label": "evil"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_assign_agent_tag(self, client, viewer_headers, settings_db):
        settings_db.create_tag("prod")
        res = client.post(
            "/api/fleet/agents/agent-1/tags",
            json={"tag_name": "prod"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_cannot_remove_agent_tag(self, client, viewer_headers):
        res = client.delete(
            "/api/fleet/agents/agent-1/tags/prod", headers=viewer_headers
        )
        assert res.status_code == 403

    def test_admin_can_write(self, client, auth_headers):
        """Sanity check: admin still succeeds on write endpoints."""
        res = client.put(
            "/api/settings/server",
            json={"jwt_ttl_hours": "4"},
            headers=auth_headers,
        )
        assert res.status_code == 200


class TestRoleValidation:
    def test_create_user_default_role_is_viewer(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "newuser", "password": "pass"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["role"] == "viewer"

    def test_create_user_valid_admin_role(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "newadmin", "password": "pass", "role": "admin"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["role"] == "admin"

    def test_create_user_invalid_role_rejected(self, client, auth_headers):
        res = client.post(
            "/api/settings/users",
            json={"username": "badrole", "password": "pass", "role": "superadmin"},
            headers=auth_headers,
        )
        assert res.status_code == 400
        assert "Invalid role" in res.json()["detail"]


class TestCustomRulesAPI:
    def test_list_empty(self, client, auth_headers):
        res = client.get("/api/threat-intel/custom-rules", headers=auth_headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_add_and_list(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/custom-rules",
            json={
                "action": "block", "stage": "fast_path",
                "rule_type": "dst_ip", "pattern": "10.0.0.1",
                "description": "test custom rule",
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert "id" in res.json()

        rules = client.get("/api/threat-intel/custom-rules", headers=auth_headers).json()
        assert len(rules) == 1
        assert rules[0]["pattern"] == "10.0.0.1"

    def test_delete(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/custom-rules",
            json={
                "action": "allow", "stage": "pre_graph",
                "rule_type": "process_name", "pattern": "safe.exe",
            },
            headers=auth_headers,
        )
        rule_id = res.json()["id"]
        del_res = client.delete(
            f"/api/threat-intel/custom-rules/{rule_id}", headers=auth_headers,
        )
        assert del_res.status_code == 200

    def test_delete_nonexistent(self, client, auth_headers):
        res = client.delete(
            "/api/threat-intel/custom-rules/99999", headers=auth_headers,
        )
        assert res.status_code == 404

    def test_invalid_action_rejected(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/custom-rules",
            json={
                "action": "nuke", "stage": "fast_path",
                "rule_type": "dst_ip", "pattern": "x",
            },
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_viewer_cannot_add(self, client, viewer_headers):
        res = client.post(
            "/api/threat-intel/custom-rules",
            json={
                "action": "block", "stage": "fast_path",
                "rule_type": "dst_ip", "pattern": "1.2.3.4",
            },
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_can_list(self, client, viewer_headers):
        res = client.get("/api/threat-intel/custom-rules", headers=viewer_headers)
        assert res.status_code == 200


class TestSuppressionsAPI:
    def test_list_empty(self, client, auth_headers):
        res = client.get("/api/threat-intel/suppressions", headers=auth_headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_add_and_list(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/suppressions",
            json={
                "indicator_type": "ip", "pattern": "8.8.8.8",
                "reason": "Google DNS",
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["pattern"] == "8.8.8.8"

        items = client.get("/api/threat-intel/suppressions", headers=auth_headers).json()
        assert len(items) == 1

    def test_delete(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/suppressions",
            json={"indicator_type": "domain", "pattern": "cdn.example.com"},
            headers=auth_headers,
        )
        sup_id = res.json()["id"]
        del_res = client.delete(
            f"/api/threat-intel/suppressions/{sup_id}", headers=auth_headers,
        )
        assert del_res.status_code == 200

    def test_delete_nonexistent(self, client, auth_headers):
        res = client.delete(
            "/api/threat-intel/suppressions/99999", headers=auth_headers,
        )
        assert res.status_code == 404

    def test_invalid_type_rejected(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/suppressions",
            json={"indicator_type": "url", "pattern": "http://x.com"},
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_duplicate_rejected(self, client, auth_headers):
        client.post(
            "/api/threat-intel/suppressions",
            json={"indicator_type": "ip", "pattern": "1.1.1.1"},
            headers=auth_headers,
        )
        res = client.post(
            "/api/threat-intel/suppressions",
            json={"indicator_type": "ip", "pattern": "1.1.1.1"},
            headers=auth_headers,
        )
        assert res.status_code == 409

    def test_viewer_cannot_add(self, client, viewer_headers):
        res = client.post(
            "/api/threat-intel/suppressions",
            json={"indicator_type": "ip", "pattern": "1.2.3.4"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_can_list(self, client, viewer_headers):
        res = client.get("/api/threat-intel/suppressions", headers=viewer_headers)
        assert res.status_code == 200


class TestSigmaToggleAPI:
    def test_list_disabled_empty(self, client, auth_headers):
        res = client.get("/api/threat-intel/sigma/disabled", headers=auth_headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_toggle_disable(self, client, auth_headers):
        res = client.post(
            "/api/threat-intel/sigma/process_name:bash/toggle",
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["rule_id"] == "process_name:bash"
        assert data["disabled"] is True

    def test_toggle_re_enable(self, client, auth_headers):
        # Disable
        client.post(
            "/api/threat-intel/sigma/process_name:bash/toggle",
            headers=auth_headers,
        )
        # Re-enable
        res = client.post(
            "/api/threat-intel/sigma/process_name:bash/toggle",
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["disabled"] is False

    def test_disabled_appears_in_list(self, client, auth_headers):
        client.post(
            "/api/threat-intel/sigma/file_path:/tmp/*/toggle",
            headers=auth_headers,
        )
        res = client.get("/api/threat-intel/sigma/disabled", headers=auth_headers)
        items = res.json()
        assert len(items) == 1
        assert items[0]["rule_id"] == "file_path:/tmp/*"

    def test_viewer_cannot_toggle(self, client, viewer_headers):
        res = client.post(
            "/api/threat-intel/sigma/process_name:bash/toggle",
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_viewer_can_list_disabled(self, client, viewer_headers):
        res = client.get("/api/threat-intel/sigma/disabled", headers=viewer_headers)
        assert res.status_code == 200
