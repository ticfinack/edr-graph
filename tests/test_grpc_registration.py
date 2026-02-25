"""Tests for FleetServicer.RegisterAgent re-registration logic.

Covers the settings_db code path: re-registration with same key skips
use_count increment, re-registration with different key goes through
normal validation, and revoked/expired keys are rejected on re-registration.
"""

from unittest.mock import MagicMock

import pytest

from server.settings_db import SettingsDB


@pytest.fixture
def settings_db(tmp_path):
    db = SettingsDB(tmp_path / "settings.db")
    yield db
    db.close()


@pytest.fixture
def neo4j():
    mock = MagicMock()
    mock.register_agent = MagicMock()
    return mock


@pytest.fixture
def grpc_context():
    ctx = MagicMock()
    ctx.peer.return_value = "ipv4:127.0.0.1:9999"
    return ctx


def _make_servicer(neo4j, settings_db):
    from server.grpc_service import FleetServicer

    return FleetServicer(neo4j=neo4j, settings_db=settings_db)


def _make_request(agent_id="agent-1", reg_key="key-abc", hostname="testhost"):
    from agent.fleet.proto import fleet_pb2

    return fleet_pb2.RegisterAgentRequest(
        agent_info=fleet_pb2.AgentInfo(
            agent_id=agent_id,
            hostname=hostname,
            platform="linux",
            os_version="6.x",
            agent_version="0.1.0",
            ip_address="10.0.0.1",
            registered_at=1700000000,
        ),
        registration_key=reg_key,
    )


class TestFirstRegistration:
    """First-time registration should increment use_count."""

    def test_first_registration_increments_use_count(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(key="key-abc", label="test", created_by="admin")
        servicer = _make_servicer(neo4j, settings_db)

        resp = servicer.RegisterAgent(_make_request(), grpc_context)

        assert resp.accepted is True
        keys = settings_db.list_registration_keys()
        assert keys[0]["use_count"] == 1

    def test_first_registration_stores_agent_key_mapping(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(key="key-abc", label="test", created_by="admin")
        servicer = _make_servicer(neo4j, settings_db)

        servicer.RegisterAgent(_make_request(), grpc_context)

        assert settings_db.get_agent_key("agent-1") == "key-abc"


class TestReRegistrationSameKey:
    """Re-registration with the same key should NOT increment use_count."""

    def test_reregistration_does_not_increment_use_count(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(key="key-abc", label="test", created_by="admin")
        servicer = _make_servicer(neo4j, settings_db)

        # First registration
        servicer.RegisterAgent(_make_request(), grpc_context)
        # Simulate restart: re-register same agent with same key
        resp = servicer.RegisterAgent(_make_request(), grpc_context)

        assert resp.accepted is True
        keys = settings_db.list_registration_keys()
        assert keys[0]["use_count"] == 1  # NOT 2

    def test_many_reregistrations_use_count_stays_at_one(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(
            key="key-abc", label="test", created_by="admin", max_uses=2,
        )
        servicer = _make_servicer(neo4j, settings_db)

        servicer.RegisterAgent(_make_request(), grpc_context)
        for _ in range(50):
            resp = servicer.RegisterAgent(_make_request(), grpc_context)
            assert resp.accepted is True

        keys = settings_db.list_registration_keys()
        assert keys[0]["use_count"] == 1

    def test_reregistration_with_exhausted_key_succeeds(self, neo4j, settings_db, grpc_context):
        """An agent whose key is exhausted can still re-register."""
        settings_db.create_registration_key(
            key="key-abc", label="test", created_by="admin", max_uses=1,
        )
        servicer = _make_servicer(neo4j, settings_db)

        # First registration exhausts the key (use_count 0 -> 1, max_uses=1)
        resp = servicer.RegisterAgent(_make_request(), grpc_context)
        assert resp.accepted is True
        # Re-registration should still work — it's the same agent
        resp = servicer.RegisterAgent(_make_request(), grpc_context)
        assert resp.accepted is True

        keys = settings_db.list_registration_keys()
        assert keys[0]["use_count"] == 1
        assert keys[0]["status"] == "exhausted"


class TestReRegistrationDifferentKey:
    """Re-registration with a different key should go through normal validation."""

    def test_different_key_increments_new_key_use_count(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(key="key-old", label="old", created_by="admin")
        settings_db.create_registration_key(key="key-new", label="new", created_by="admin")
        servicer = _make_servicer(neo4j, settings_db)

        # Register with old key
        servicer.RegisterAgent(_make_request(reg_key="key-old"), grpc_context)
        # Re-register with different key
        resp = servicer.RegisterAgent(_make_request(reg_key="key-new"), grpc_context)

        assert resp.accepted is True
        keys = {k["label"]: k for k in settings_db.list_registration_keys()}
        assert keys["old"]["use_count"] == 1
        assert keys["new"]["use_count"] == 1
        # Agent should now be mapped to new key
        assert settings_db.get_agent_key("agent-1") == "key-new"


class TestReRegistrationRevokedExpired:
    """Re-registration should fail if the key has been revoked or expired."""

    def test_reregistration_with_revoked_key_rejected(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(key="key-abc", label="test", created_by="admin")
        servicer = _make_servicer(neo4j, settings_db)

        # Register first
        servicer.RegisterAgent(_make_request(), grpc_context)
        # Revoke the key
        settings_db.revoke_registration_key("key-abc", revoked_by="admin")
        # Re-register should fail
        resp = servicer.RegisterAgent(_make_request(), grpc_context)

        assert resp.accepted is False
        assert resp.message == "key_revoked"

    def test_reregistration_with_expired_key_rejected(self, neo4j, settings_db, grpc_context):
        settings_db.create_registration_key(
            key="key-abc", label="test", created_by="admin", expires_at=1,
        )
        servicer = _make_servicer(neo4j, settings_db)

        # Manually set agent_key_map (can't register with already-expired key)
        settings_db.set_agent_key("agent-1", "key-abc")
        # Re-register should fail because key is expired
        resp = servicer.RegisterAgent(_make_request(), grpc_context)

        assert resp.accepted is False
        assert resp.message == "key_expired"


class TestNoRegistrationKey:
    def test_missing_key_rejected(self, neo4j, settings_db, grpc_context):
        servicer = _make_servicer(neo4j, settings_db)
        resp = servicer.RegisterAgent(_make_request(reg_key=""), grpc_context)
        assert resp.accepted is False
        assert resp.message == "registration_key is required"


class TestNeo4jOnlyMode:
    """Without settings_db, re-registration detection is unavailable."""

    def test_neo4j_only_always_validates_via_neo4j(self, neo4j, grpc_context):
        neo4j.validate_registration_key.return_value = (True, "ok")
        servicer = _make_servicer(neo4j, settings_db=None)

        resp = servicer.RegisterAgent(_make_request(), grpc_context)
        assert resp.accepted is True
        neo4j.validate_registration_key.assert_called_once_with("key-abc")

    def test_neo4j_only_increments_every_time(self, neo4j, grpc_context):
        neo4j.validate_registration_key.return_value = (True, "ok")
        servicer = _make_servicer(neo4j, settings_db=None)

        servicer.RegisterAgent(_make_request(), grpc_context)
        servicer.RegisterAgent(_make_request(), grpc_context)
        # Without settings_db, every call goes through neo4j.validate
        assert neo4j.validate_registration_key.call_count == 2
