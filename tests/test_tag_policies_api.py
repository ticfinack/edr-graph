"""Tests for tag policy REST endpoints in server/dashboard.py."""

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
    class FakeSettings:
        jwt_secret = "test-secret-key-for-jwt-at-least-32-bytes-long"
        jwt_ttl_hours = 8
        grpc_port = 50051
        http_port = 8080
        neo4j_uri = "bolt://localhost:7687"

    return FakeSettings()


class FakeNeo4j:
    """Minimal mock for Neo4j client — only fleet status is needed."""

    def get_fleet_status(self):
        return [
            {"agent_id": "agent-1", "hostname": "host1", "status": "online", "finding_count": 0},
            {"agent_id": "agent-2", "hostname": "host2", "status": "offline", "finding_count": 3},
        ]


@pytest.fixture
def client(settings_db, mock_settings):
    set_jwt_secret(mock_settings.jwt_secret)
    set_settings(mock_settings)
    set_settings_db(settings_db)
    set_neo4j(FakeNeo4j())
    settings_db.create_user("admin", hash_password("password"), role="admin")
    return TestClient(app)


@pytest.fixture
def auth_headers(mock_settings):
    token = create_token("admin", "admin", mock_settings.jwt_secret, ttl_hours=1)
    return {"Authorization": f"Bearer {token}"}


class TestTagCRUDEndpoints:
    def test_list_tags_empty(self, client, auth_headers):
        res = client.get("/api/settings/tags", headers=auth_headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_create_tag(self, client, auth_headers):
        res = client.post(
            "/api/settings/tags",
            json={"tag_name": "production", "description": "Prod hosts", "color": "#ef4444", "priority": 10},
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["tag_name"] == "production"
        assert data["priority"] == 10

    def test_create_tag_invalid_name(self, client, auth_headers):
        res = client.post(
            "/api/settings/tags",
            json={"tag_name": "INVALID"},
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_create_duplicate_tag(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        assert res.status_code == 409

    def test_get_tag(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "staging"}, headers=auth_headers)
        res = client.get("/api/settings/tags/staging", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["tag_name"] == "staging"

    def test_get_tag_not_found(self, client, auth_headers):
        res = client.get("/api/settings/tags/ghost", headers=auth_headers)
        assert res.status_code == 404

    def test_update_tag(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "dev"}, headers=auth_headers)
        res = client.put(
            "/api/settings/tags/dev",
            json={"description": "Development", "priority": 5},
            headers=auth_headers,
        )
        assert res.status_code == 200

        tag = client.get("/api/settings/tags/dev", headers=auth_headers).json()
        assert tag["description"] == "Development"
        assert tag["priority"] == 5

    def test_update_tag_not_found(self, client, auth_headers):
        res = client.put("/api/settings/tags/ghost", json={"description": "x"}, headers=auth_headers)
        assert res.status_code == 404

    def test_delete_tag(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "temp"}, headers=auth_headers)
        res = client.delete("/api/settings/tags/temp", headers=auth_headers)
        assert res.status_code == 200
        assert client.get("/api/settings/tags/temp", headers=auth_headers).status_code == 404

    def test_delete_tag_not_found(self, client, auth_headers):
        res = client.delete("/api/settings/tags/ghost", headers=auth_headers)
        assert res.status_code == 404

    def test_list_tags_with_counts(self, client, auth_headers, settings_db):
        client.post("/api/settings/tags", json={"tag_name": "prod", "priority": 10}, headers=auth_headers)
        client.post("/api/settings/tags", json={"tag_name": "dev", "priority": 0}, headers=auth_headers)
        settings_db.assign_tag("agent-1", "prod")
        settings_db.assign_tag("agent-2", "prod")

        tags = client.get("/api/settings/tags", headers=auth_headers).json()
        assert len(tags) == 2
        # Sorted by priority: dev(0) first, prod(10) second
        assert tags[0]["tag_name"] == "dev"
        assert tags[0]["agent_count"] == 0
        assert tags[1]["tag_name"] == "prod"
        assert tags[1]["agent_count"] == 2


class TestTagPolicyEndpoints:
    def test_get_policy_empty(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.get("/api/settings/tags/prod/policy", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["overrides"] == {}
        assert data["rules"] == []

    def test_set_and_get_policy(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.put(
            "/api/settings/tags/prod/policy",
            json={"overrides": {"response_mode": "enforcing", "auto_respond": "true"}},
            headers=auth_headers,
        )
        assert res.status_code == 200

        policy = client.get("/api/settings/tags/prod/policy", headers=auth_headers).json()
        assert policy["overrides"]["response_mode"] == "enforcing"
        assert policy["overrides"]["auto_respond"] == "true"

    def test_set_policy_with_rules(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        rules = [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
            {"action": "allow", "stage": "pre_graph", "rule_type": "dst_ip", "pattern": "10.0.0.1"},
        ]
        res = client.put(
            "/api/settings/tags/prod/policy",
            json={"overrides": {"response_mode": "enforcing"}, "rules": rules},
            headers=auth_headers,
        )
        assert res.status_code == 200

        policy = client.get("/api/settings/tags/prod/policy", headers=auth_headers).json()
        assert policy["overrides"]["response_mode"] == "enforcing"
        assert len(policy["rules"]) == 2
        assert policy["rules"][0]["pattern"] == "mimikatz"
        assert policy["rules"][1]["pattern"] == "10.0.0.1"

    def test_set_policy_rules_only(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.put(
            "/api/settings/tags/prod/policy",
            json={"rules": [
                {"action": "block", "stage": "fast_path", "rule_type": "domain", "pattern": "evil.com"},
            ]},
            headers=auth_headers,
        )
        assert res.status_code == 200

        policy = client.get("/api/settings/tags/prod/policy", headers=auth_headers).json()
        assert policy["overrides"] == {}
        assert len(policy["rules"]) == 1

    def test_set_policy_tag_not_found(self, client, auth_headers):
        res = client.put(
            "/api/settings/tags/ghost/policy",
            json={"overrides": {"response_mode": "enforcing"}},
            headers=auth_headers,
        )
        assert res.status_code == 404

    def test_get_policy_tag_not_found(self, client, auth_headers):
        res = client.get("/api/settings/tags/ghost/policy", headers=auth_headers)
        assert res.status_code == 404


class TestAgentTagEndpoints:
    def test_assign_and_get_agent_tags(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.post(
            "/api/fleet/agents/agent-1/tags",
            json={"tag_name": "prod"},
            headers=auth_headers,
        )
        assert res.status_code == 200

        tags = client.get("/api/fleet/agents/agent-1/tags", headers=auth_headers).json()
        assert len(tags) == 1
        assert tags[0]["tag_name"] == "prod"

    def test_assign_nonexistent_tag(self, client, auth_headers):
        res = client.post(
            "/api/fleet/agents/agent-1/tags",
            json={"tag_name": "ghost"},
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_remove_agent_tag(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        client.post("/api/fleet/agents/agent-1/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.delete("/api/fleet/agents/agent-1/tags/prod", headers=auth_headers)
        assert res.status_code == 200

        tags = client.get("/api/fleet/agents/agent-1/tags", headers=auth_headers).json()
        assert tags == []

    def test_remove_tag_not_assigned(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        res = client.delete("/api/fleet/agents/agent-1/tags/prod", headers=auth_headers)
        assert res.status_code == 404


class TestResolvedConfig:
    def test_resolved_config_no_tags(self, client, auth_headers):
        res = client.get("/api/fleet/agents/agent-1/resolved-config", headers=auth_headers)
        assert res.status_code == 200
        config = res.json()
        assert config["response_mode"] == "learning"
        assert "rules" in config
        assert isinstance(config["rules"], list)

    def test_resolved_config_with_tags(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod", "priority": 10}, headers=auth_headers)
        client.put(
            "/api/settings/tags/prod/policy",
            json={"overrides": {"response_mode": "enforcing"}},
            headers=auth_headers,
        )
        client.post("/api/fleet/agents/agent-1/tags", json={"tag_name": "prod"}, headers=auth_headers)

        config = client.get("/api/fleet/agents/agent-1/resolved-config", headers=auth_headers).json()
        assert config["response_mode"] == "enforcing"
        assert config["analyzer_interval"] == "60.0"  # unchanged default

    def test_resolved_config_includes_rules(self, client, auth_headers):
        client.post("/api/settings/tags", json={"tag_name": "prod"}, headers=auth_headers)
        client.put(
            "/api/settings/tags/prod/policy",
            json={"rules": [
                {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "evil"},
            ]},
            headers=auth_headers,
        )
        client.post("/api/fleet/agents/agent-1/tags", json={"tag_name": "prod"}, headers=auth_headers)

        config = client.get("/api/fleet/agents/agent-1/resolved-config", headers=auth_headers).json()
        assert len(config["rules"]) == 1
        assert config["rules"][0]["pattern"] == "evil"


class TestAgentsListIncludesTags:
    def test_fleet_agents_have_tags(self, client, auth_headers, settings_db):
        settings_db.create_tag("prod", color="#ef4444")
        settings_db.assign_tag("agent-1", "prod")

        agents = client.get("/api/fleet/agents", headers=auth_headers).json()
        agent1 = next(a for a in agents if a["agent_id"] == "agent-1")
        assert len(agent1["tags"]) == 1
        assert agent1["tags"][0]["tag_name"] == "prod"
        assert agent1["tags"][0]["color"] == "#ef4444"

        agent2 = next(a for a in agents if a["agent_id"] == "agent-2")
        assert agent2["tags"] == []


class TestAuthRequired:
    def test_tags_require_auth(self, client):
        assert client.get("/api/settings/tags").status_code == 401
        assert client.post("/api/settings/tags", json={"tag_name": "x"}).status_code == 401

    def test_agent_tags_require_auth(self, client):
        assert client.get("/api/fleet/agents/a/tags").status_code == 401
        assert client.post("/api/fleet/agents/a/tags", json={"tag_name": "x"}).status_code == 401

    def test_resolved_config_requires_auth(self, client):
        assert client.get("/api/fleet/agents/a/resolved-config").status_code == 401
