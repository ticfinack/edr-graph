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
    def setup_method(self):
        """Clear sshd cache between tests to avoid cross-test pollution."""
        from agent.processor.entity_extractor import _sshd_cache

        _sshd_cache.clear()

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
        mock_proc.info = {"pid": 800, "name": "sshd", "create_time": 1700000000.0, "ppid": 1}

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
        # UNION branches should be wrapped in CALL {} subquery
        assert "CALL {" in query

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
        # UNION branches should be wrapped in CALL {} subquery
        assert "CALL {" in query

    def test_detect_lateral_movements_no_time_window_param(self):
        """The new query should not accept a time_window parameter."""
        import inspect

        from server.neo4j_client import Neo4jClient

        sig = inspect.signature(Neo4jClient.detect_lateral_movements)
        assert "time_window" not in sig.parameters


class TestLateralMovementDetail:
    """Verify 3-phase XDR stitching in get_lateral_movement_detail()."""

    def _make_client(self):
        from server.neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client._driver = MagicMock()
        return client

    def _mock_session(self, client):
        mock_session = MagicMock()
        client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client._driver.session.return_value.__exit__ = MagicMock(return_value=False)
        return mock_session

    def _phase1_record(self, **overrides):
        """Build a mock Phase 1 record with sane defaults."""
        defaults = {
            "dst_agent_id": "agent-victim",
            "dst_hostname": "victim-host",
            "dst_ip_addresses": ["10.0.0.20"],
            "finding_id": "f-001",
            "title": "SSH lateral movement",
            "severity": "high",
            "timestamp": 1700000000,
            "description": "Lateral movement via SSH detected",
            "victim_chain": [
                {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
                 "pid": 500, "timestamp": 1700000000, "step_index": 0},
                {"entity_type": "process", "entity_id": "zsh", "entity_name": "zsh",
                 "pid": 501, "timestamp": 1700000001, "step_index": 1},
            ],
            "pivot_ip": "10.0.0.10",
            "src_agent_id": "agent-source",
            "src_hostname": "source-host",
        }
        defaults.update(overrides)
        record = MagicMock()
        record.single.return_value = MagicMock()
        record.single.return_value.__getitem__ = lambda s, k: defaults[k]
        record.single.return_value.__contains__ = lambda s, k: k in defaults
        record.single.return_value.keys = lambda: list(defaults.keys())

        # Make dict(record.single()) work
        class DictableRecord:
            def __init__(self, data):
                self._data = data

            def __getitem__(self, key):
                return self._data[key]

            def __contains__(self, key):
                return key in self._data

            def keys(self):
                return self._data.keys()

            def values(self):
                return self._data.values()

            def items(self):
                return self._data.items()

            def get(self, key, default=None):
                return self._data.get(key, default)

        dictable = DictableRecord(defaults)
        record.single.return_value = dictable
        return record

    def test_returns_pivot_ip_in_response(self):
        """Verify pivot_ip is a top-level key in the return dict."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: [
            {"entity_type": "process", "entity_id": "bash", "entity_name": "bash",
             "pid": 100, "timestamp": 1700000000, "step_index": 0},
        ]
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase1_record(),
            phase2a_result,
        ]

        result = client.get_lateral_movement_detail("f-001")

        assert "pivot_ip" in result
        assert result["pivot_ip"] == "10.0.0.10"

    def test_returns_source_and_victim_chains(self):
        """Verify separate source_chain and victim_chain lists with correct content."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        source_steps = [
            {"entity_type": "process", "entity_id": "bash", "entity_name": "bash",
             "pid": 100, "timestamp": 1700000000, "step_index": 0},
            {"entity_type": "process", "entity_id": "ssh", "entity_name": "ssh",
             "pid": 101, "timestamp": 1700000001, "step_index": 1},
        ]
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: source_steps
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase1_record(),
            phase2a_result,
        ]

        result = client.get_lateral_movement_detail("f-001")

        assert "source_chain" in result
        assert "victim_chain" in result
        assert len(result["source_chain"]) == 2
        assert result["source_chain"][0]["entity_name"] == "bash"
        assert result["source_chain"][1]["entity_name"] == "ssh"
        assert len(result["victim_chain"]) == 2
        assert result["victim_chain"][0]["entity_name"] == "sshd"
        # Old 'chain' key should not be present
        assert "chain" not in result

    def test_fallback_to_process_connected_to_ip(self):
        """Phase 2A returns empty → Phase 2B synthetic chain has process steps."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        # Phase 2A returns empty
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        # Phase 2B returns process->IP rows
        phase2b_row1 = MagicMock()
        phase2b_row1.__getitem__ = lambda s, k: {"process_name": "ssh", "ip_address": "10.0.0.20"}[k]
        phase2b_result = MagicMock()
        phase2b_result.__iter__ = lambda s: iter([phase2b_row1])

        mock_session.run.side_effect = [
            self._phase1_record(),
            phase2a_result,
            phase2b_result,
        ]

        result = client.get_lateral_movement_detail("f-001")

        assert len(result["source_chain"]) == 2
        assert result["source_chain"][0]["entity_type"] == "process"
        assert result["source_chain"][0]["entity_name"] == "ssh"
        assert result["source_chain"][1]["entity_type"] == "ip"
        assert result["source_chain"][1]["entity_id"] == "10.0.0.20"

    def test_empty_result_when_finding_not_found(self):
        """Returns {} for nonexistent finding_id."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase1_result = MagicMock()
        phase1_result.single.return_value = None
        mock_session.run.side_effect = [phase1_result]

        result = client.get_lateral_movement_detail("nonexistent")

        assert result == {}

    def test_query_includes_involves_ip(self):
        """Phase 1 Cypher includes both INVOLVES_IP and entity_type = 'ip'."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase1_result = MagicMock()
        phase1_result.single.return_value = None
        mock_session.run.side_effect = [phase1_result]

        client.get_lateral_movement_detail("f-check")

        # Phase 1 query should reference both detection paths
        phase1_query = mock_session.run.call_args_list[0][0][0]
        assert "INVOLVES_IP" in phase1_query
        assert "entity_type = 'ip'" in phase1_query
