"""Tests for lateral movement & privilege escalation detection pipeline.

Covers:
- Chain builder fallback with Authentication events
- Entity extractor inbound auth edges
- Neo4j lateral/vertical movement query shapes (mocked driver)
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.processor.entity_extractor import extract_entities
from agent.schema.ocsf_types import (
    Authentication,
    DeviceInfo,
    NetworkEndpoint,
    UserInfo,
)

# ── Chain builder tests ─────────────────────────────────────────────


class TestChainBuilderAuthentication:
    """Test _build_chain_from_events with Authentication events."""

    @staticmethod
    def _build(events):
        """Call _build_chain_from_events as unbound (it doesn't use self)."""
        return LlmAnalyzer._build_chain_from_events(None, events)

    def test_auth_with_src_ip_produces_user_and_ip_steps(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="attacker"),
            src_endpoint=NetworkEndpoint(ip="10.0.0.50"),
            device=DeviceInfo(hostname="victim-host"),
        )
        chain = self._build([(1, event)])

        assert len(chain) == 2
        assert chain[0].entity_type == "user"
        assert chain[0].entity_id == "attacker"
        assert chain[0].entity_name == "attacker"
        assert chain[1].entity_type == "ip"
        assert chain[1].entity_id == "10.0.0.50"

    def test_auth_without_src_endpoint_produces_user_only(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="localuser"),
            device=DeviceInfo(hostname="host1"),
        )
        chain = self._build([(2, event)])

        assert len(chain) == 1
        assert chain[0].entity_type == "user"
        assert chain[0].entity_id == "localuser"

    def test_auth_with_src_endpoint_no_ip_produces_user_only(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="bob"),
            src_endpoint=NetworkEndpoint(ip=""),
            device=DeviceInfo(hostname="host1"),
        )
        chain = self._build([(3, event)])

        # Empty IP string is falsy, should only get user step
        assert len(chain) == 1
        assert chain[0].entity_type == "user"


# ── Entity extractor auth edge tests ────────────────────────────────


class TestAuthenticationEntityExtraction:
    def test_auth_creates_inbound_edge_when_sshd_found(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="root"),
            src_endpoint=NetworkEndpoint(ip="192.168.1.100"),
            device=DeviceInfo(hostname="target"),
        )

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 800, "name": "sshd", "create_time": 1700000000.0}

        with patch("psutil.process_iter", return_value=[mock_proc]):
            entities = extract_entities(event, event_id=10)

        assert len(entities.ips) == 1
        assert entities.ips[0].id == "192.168.1.100"
        assert len(entities.connected_edges) == 1
        edge = entities.connected_edges[0]
        assert edge["ip_id"] == "192.168.1.100"
        assert edge["direction"] == "inbound"
        assert edge["dst_port"] == 22
        assert edge["process_id"] == "target:800:1700000000"

    def test_auth_no_edge_when_sshd_not_found(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="root"),
            src_endpoint=NetworkEndpoint(ip="192.168.1.100"),
            device=DeviceInfo(hostname="target"),
        )

        with patch("psutil.process_iter", return_value=[]):
            entities = extract_entities(event, event_id=11)

        # IP still extracted, but no connected edge
        assert len(entities.ips) == 1
        assert len(entities.connected_edges) == 0

    def test_auth_no_src_endpoint_no_edge(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="localuser"),
            device=DeviceInfo(hostname="host1"),
        )
        entities = extract_entities(event, event_id=12)

        assert len(entities.users) == 1
        assert len(entities.ips) == 0
        assert len(entities.connected_edges) == 0


# ── Neo4j query shape tests (mocked driver) ─────────────────────────


class TestNeo4jLateralMovement:
    """Verify the Neo4j queries are well-formed by running them against a mock."""

    def _make_client(self):
        from server.neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client._driver = MagicMock()
        return client

    def test_detect_lateral_movements_query_runs(self):
        client = self._make_client()
        mock_session = MagicMock()
        mock_session.run.return_value = []
        client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client._driver.session.return_value.__exit__ = MagicMock(return_value=False)

        result = client.detect_lateral_movements(limit=10)

        assert result == []
        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        # Should use Host.ip_addresses, not Process-CONNECTED_TO->IP
        assert "ip_addresses" in query
        assert "CONNECTED_TO" not in query

    def test_detect_vertical_movements_query_runs(self):
        client = self._make_client()
        mock_session = MagicMock()
        mock_session.run.return_value = []
        client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client._driver.session.return_value.__exit__ = MagicMock(return_value=False)

        result = client.detect_vertical_movements(limit=10)

        assert result == []
        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        assert "entity_type = 'user'" in query
        assert "entity_name = 'root'" in query

    def test_get_host_to_host_connections_query_runs(self):
        client = self._make_client()
        mock_session = MagicMock()
        mock_session.run.return_value = []
        client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client._driver.session.return_value.__exit__ = MagicMock(return_value=False)

        result = client.get_host_to_host_connections(limit=10)

        assert result == []
        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        assert "ip_addresses" in query
        assert "Process)-[:CONNECTED_TO]" not in query

    def test_detect_lateral_movements_no_time_window_param(self):
        """The new query should not accept a time_window parameter."""
        import inspect

        from server.neo4j_client import Neo4jClient

        sig = inspect.signature(Neo4jClient.detect_lateral_movements)
        assert "time_window" not in sig.parameters
