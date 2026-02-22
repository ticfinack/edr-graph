"""Tests for config push via heartbeat: HMAC signing, agent verification, and config application."""

import hashlib
import hmac
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from agent.config import Settings
from agent.queue.sqlite_queue import SqliteQueue

_has_grpc = bool(sys.modules.get("grpc"))
if not _has_grpc:
    try:
        import grpc as _grpc  # noqa: F401

        _has_grpc = True
    except ImportError:
        pass


@pytest.fixture
def queue(tmp_path):
    q = SqliteQueue(tmp_path / "test.db")
    yield q
    q.close()


@pytest.fixture
def settings(tmp_path):
    s = Settings(
        data_dir=tmp_path,
        fleet_registration_key="test-reg-key-abc123",
        response_mode="learning",
        analyzer_interval=60.0,
        collector_poll_interval=1.0,
    )
    return s


def _sign(config_json: str, key: str) -> str:
    return hmac.new(key.encode(), config_json.encode(), hashlib.sha256).hexdigest()


@pytest.mark.skipif(not _has_grpc, reason="grpc not installed")
class TestConfigPushVerification:
    def test_valid_signature_accepted(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({"response_mode": "enforcing"})
        sig = _sign(config, "test-reg-key-abc123")

        fwd._apply_config_overrides(config, sig)
        assert settings.response_mode == "enforcing"

    def test_invalid_signature_rejected(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({"response_mode": "enforcing"})
        fwd._apply_config_overrides(config, "bad-signature")
        # Should remain unchanged
        assert settings.response_mode == "learning"

    def test_empty_signature_rejected(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({"response_mode": "enforcing"})
        fwd._apply_config_overrides(config, "")
        assert settings.response_mode == "learning"

    def test_no_registration_key_rejects_all(self, queue, tmp_path):
        from agent.fleet.forwarder import FleetForwarder

        s = Settings(data_dir=tmp_path, fleet_registration_key="")
        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(s, queue)

        config = json.dumps({"response_mode": "enforcing"})
        sig = _sign(config, "")
        fwd._apply_config_overrides(config, sig)
        assert s.response_mode == "learning"

    def test_tampered_config_rejected(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        original = json.dumps({"response_mode": "enforcing"})
        sig = _sign(original, "test-reg-key-abc123")
        # Tamper with the config after signing
        tampered = json.dumps({"response_mode": "enforcing", "auto_terminate": "true"})
        fwd._apply_config_overrides(tampered, sig)
        assert settings.response_mode == "learning"  # not applied


@pytest.mark.skipif(not _has_grpc, reason="grpc not installed")
class TestConfigOverrideApplication:
    def test_whitelisted_keys_applied(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({
            "response_mode": "enforcing",
            "analyzer_interval": "30.0",
            "collector_poll_interval": "2.5",
            "novel_edge_threshold": "10",
            "dga_score_threshold": "0.8",
            "graph_ttl_hours": "48",
            "auto_respond": "true",
            "auto_terminate": "false",
            "fleet_forward_events": "true",
            "ioc_feeds_enabled": "false",
        })
        sig = _sign(config, "test-reg-key-abc123")
        fwd._apply_config_overrides(config, sig)

        assert settings.response_mode == "enforcing"
        assert settings.analyzer_interval == 30.0
        assert settings.collector_poll_interval == 2.5
        assert settings.novel_edge_threshold == 10
        assert settings.dga_score_threshold == 0.8
        assert settings.graph_ttl_hours == 48
        assert settings.auto_respond is True
        assert settings.auto_terminate is False
        assert settings.fleet_forward_events is True
        assert settings.ioc_feeds_enabled is False

    def test_unknown_keys_ignored(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({
            "response_mode": "enforcing",
            "evil_setting": "injected",
            "data_dir": "/etc/shadow",
        })
        sig = _sign(config, "test-reg-key-abc123")
        fwd._apply_config_overrides(config, sig)

        assert settings.response_mode == "enforcing"
        assert not hasattr(settings, "evil_setting")
        assert str(settings.data_dir) != "/etc/shadow"

    def test_bad_json_ignored(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        bad_json = "not-json{"
        sig = _sign(bad_json, "test-reg-key-abc123")
        fwd._apply_config_overrides(bad_json, sig)
        # Should not crash, settings unchanged
        assert settings.response_mode == "learning"

    def test_empty_config_noop(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        fwd._apply_config_overrides("", "")
        assert settings.response_mode == "learning"

    def test_bool_conversion(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        for truthy in ["true", "True", "1", "yes"]:
            config = json.dumps({"auto_respond": truthy})
            sig = _sign(config, "test-reg-key-abc123")
            fwd._apply_config_overrides(config, sig)
            assert settings.auto_respond is True

        for falsy in ["false", "False", "0", "no"]:
            config = json.dumps({"auto_respond": falsy})
            sig = _sign(config, "test-reg-key-abc123")
            fwd._apply_config_overrides(config, sig)
            assert settings.auto_respond is False


@pytest.mark.skipif(not _has_grpc, reason="grpc not installed")
class TestRulesDistribution:
    def test_rules_extracted_and_applied(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder
        from agent.response.baseline import ResponseAllowlist, ResponseBlocklist

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        allowlist = ResponseAllowlist(settings.data_dir / "test.db")
        blocklist = ResponseBlocklist(settings.data_dir / "test.db")
        mock_fast = MagicMock()
        mock_cache = MagicMock()
        fwd.set_enforcement_stages(
            allowlist=allowlist,
            blocklist=blocklist,
            fast_blocklist=mock_fast,
            allowlist_cache=mock_cache,
        )

        config = json.dumps({
            "response_mode": "enforcing",
            "rules": [
                {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
                {"action": "allow", "stage": "pre_graph", "rule_type": "dst_ip", "pattern": "10.0.0.1"},
            ],
        })
        sig = _sign(config, "test-reg-key-abc123")
        fwd._apply_config_overrides(config, sig)

        assert settings.response_mode == "enforcing"
        # Allowlist gets pre_graph allow rules
        assert len(allowlist.get_network_rules()) == 1
        assert allowlist.get_network_rules()[0]["pattern"] == "10.0.0.1"
        # Blocklist gets fast_path block rules
        assert len(blocklist.get_network_rules()) == 1
        assert blocklist.get_network_rules()[0]["pattern"] == "mimikatz"
        # Fast blocklist also gets fast_path block rules
        mock_fast.set_network_rules.assert_called_once()
        # Allowlist cache is invalidated
        mock_cache.invalidate.assert_called_once()

    def test_rules_in_signed_payload(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder
        from agent.response.baseline import ResponseBlocklist

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        blocklist = ResponseBlocklist(settings.data_dir / "test.db")
        fwd.set_enforcement_stages(blocklist=blocklist)

        # Valid signature covers rules
        config = json.dumps({
            "rules": [
                {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "evil"},
            ],
        })
        sig = _sign(config, "test-reg-key-abc123")
        fwd._apply_config_overrides(config, sig)
        assert len(blocklist.get_network_rules()) == 1

    def test_tampered_rules_rejected(self, settings, queue):
        from agent.fleet.forwarder import FleetForwarder
        from agent.response.baseline import ResponseBlocklist

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        blocklist = ResponseBlocklist(settings.data_dir / "test.db")
        fwd.set_enforcement_stages(blocklist=blocklist)

        original = json.dumps({"rules": [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "safe"},
        ]})
        sig = _sign(original, "test-reg-key-abc123")
        tampered = json.dumps({"rules": [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "evil_injected"},
        ]})
        fwd._apply_config_overrides(tampered, sig)
        # Tampered payload rejected — no rules applied
        assert blocklist.get_network_rules() == []

    def test_no_enforcement_stages_no_crash(self, settings, queue):
        """Rules in config are silently ignored if no enforcement stages are wired."""
        from agent.fleet.forwarder import FleetForwarder

        with patch.object(FleetForwarder, "_connect"):
            fwd = FleetForwarder(settings, queue)

        config = json.dumps({
            "response_mode": "enforcing",
            "rules": [
                {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "x"},
            ],
        })
        sig = _sign(config, "test-reg-key-abc123")
        fwd._apply_config_overrides(config, sig)
        assert settings.response_mode == "enforcing"


class TestServerSideConfigSigning:
    def test_heartbeat_returns_signed_config(self, tmp_path):
        from server.grpc_service import FleetServicer
        from server.settings_db import SettingsDB
        from agent.fleet.proto import fleet_pb2

        sdb = SettingsDB(tmp_path / "settings.db")
        sdb.set_agent_key("agent-1", "regkey-abc")

        neo4j = MagicMock()
        servicer = FleetServicer(neo4j, settings_db=sdb)

        request = fleet_pb2.HeartbeatRequest(
            agent_id="agent-1", timestamp=1000, status="healthy"
        )
        context = MagicMock()

        response = servicer.Heartbeat(request, context)
        assert response.acknowledged is True
        assert response.config_json != ""
        assert response.config_signature != ""

        # Verify the signature
        expected_sig = hmac.new(
            b"regkey-abc", response.config_json.encode(), hashlib.sha256
        ).hexdigest()
        assert response.config_signature == expected_sig

        sdb.close()

    def test_heartbeat_no_signature_without_agent_key(self, tmp_path):
        from server.grpc_service import FleetServicer
        from server.settings_db import SettingsDB
        from agent.fleet.proto import fleet_pb2

        sdb = SettingsDB(tmp_path / "settings.db")

        neo4j = MagicMock()
        servicer = FleetServicer(neo4j, settings_db=sdb)

        request = fleet_pb2.HeartbeatRequest(
            agent_id="unknown-agent", timestamp=1000, status="healthy"
        )
        context = MagicMock()

        response = servicer.Heartbeat(request, context)
        assert response.acknowledged is True
        assert response.config_json != ""
        # No agent key mapping → no signature
        assert response.config_signature == ""

        sdb.close()

    def test_register_stores_agent_key(self, tmp_path):
        from server.grpc_service import FleetServicer
        from server.settings_db import SettingsDB
        from agent.fleet.proto import fleet_pb2

        sdb = SettingsDB(tmp_path / "settings.db")
        sdb.create_registration_key(key="regkey-xyz", label="Test", created_by="admin")

        neo4j = MagicMock()
        servicer = FleetServicer(neo4j, settings_db=sdb)

        agent_info = fleet_pb2.AgentInfo(
            agent_id="agent-2",
            hostname="host1",
            platform="linux",
            registered_at=1000,
        )
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=agent_info, registration_key="regkey-xyz"
        )
        context = MagicMock()
        context.peer.return_value = "ipv4:10.0.0.1:12345"

        response = servicer.RegisterAgent(request, context)
        assert response.accepted is True

        # Verify the agent→key mapping was stored
        assert sdb.get_agent_key("agent-2") == "regkey-xyz"

        sdb.close()
