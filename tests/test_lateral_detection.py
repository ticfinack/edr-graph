"""Tests for lateral movement & privilege escalation detection pipeline.

Covers:
- Chain builder fallback with Authentication events
- Chain enrichment with deep Kuzu ancestry
- Entity extractor inbound auth edges
- Neo4j lateral/vertical movement query shapes (mocked driver)
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.processor.entity_extractor import extract_entities
from agent.schema.graph_types import ChainStep
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

    def test_auth_with_src_ip_produces_user_sshd_and_ip_steps(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="attacker"),
            src_endpoint=NetworkEndpoint(ip="10.0.0.50"),
            device=DeviceInfo(hostname="victim-host"),
        )
        chain = self._build([(1, event)])

        assert len(chain) == 3
        assert chain[0].entity_type == "user"
        assert chain[0].entity_id == "attacker"
        assert chain[0].entity_name == "attacker"
        assert chain[1].entity_type == "process"
        assert chain[1].entity_name == "sshd"
        assert chain[1].pid is None
        assert chain[2].entity_type == "ip"
        assert chain[2].entity_id == "10.0.0.50"

    def test_auth_without_src_endpoint_produces_user_and_sshd(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="localuser"),
            device=DeviceInfo(hostname="host1"),
        )
        chain = self._build([(2, event)])

        assert len(chain) == 2
        assert chain[0].entity_type == "user"
        assert chain[0].entity_id == "localuser"
        assert chain[1].entity_type == "process"
        assert chain[1].entity_name == "sshd"

    def test_auth_with_src_endpoint_no_ip_produces_user_and_sshd(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="bob"),
            src_endpoint=NetworkEndpoint(ip=""),
            device=DeviceInfo(hostname="host1"),
        )
        chain = self._build([(3, event)])

        # Empty IP string is falsy, should get user + sshd steps
        assert len(chain) == 2
        assert chain[0].entity_type == "user"
        assert chain[1].entity_type == "process"
        assert chain[1].entity_name == "sshd"


# ── Chain enrichment tests ──────────────────────────────────────────


class TestChainEnrichment:
    """Test _enrich_chain_with_ancestry and Auth sshd anchor."""

    @staticmethod
    def _make_analyzer():
        """Create a minimal LlmAnalyzer with mocked dependencies."""
        analyzer = LlmAnalyzer.__new__(LlmAnalyzer)
        analyzer._kuzu_db = MagicMock()
        analyzer._settings = MagicMock()
        analyzer._queue = None
        analyzer._ioc_db = None
        analyzer._client = None
        analyzer._tools = []
        analyzer._graph_conn = None
        return analyzer

    @patch("agent.analyzer.llm_analyzer.get_process_chain")
    @patch("agent.analyzer.llm_analyzer.kuzu")
    def test_enrich_replaces_shallow_with_deep_ancestry(self, mock_kuzu, mock_get_chain):
        mock_get_chain.return_value = [
            {"type": "user", "id": "root", "name": "root"},
            {"name": "launchd", "pid": 1, "id": "host:1:100"},
            {"name": "sshd", "pid": 500, "id": "host:500:200"},
        ]
        analyzer = self._make_analyzer()

        chain = [
            ChainStep(entity_type="process", entity_id="sshd", entity_name="sshd", pid=500),
            ChainStep(entity_type="ip", entity_id="10.0.0.1", entity_name="10.0.0.1"),
        ]
        result = analyzer._enrich_chain_with_ancestry(chain)

        assert len(result) == 4
        assert result[0].entity_type == "user"
        assert result[0].entity_name == "root"
        assert result[1].entity_type == "process"
        assert result[1].entity_name == "launchd"
        assert result[1].pid == 1
        assert result[2].entity_type == "process"
        assert result[2].entity_name == "sshd"
        assert result[2].pid == 500
        assert result[3].entity_type == "ip"
        assert result[3].entity_id == "10.0.0.1"

    def test_enrich_preserves_chain_when_no_pid(self):
        analyzer = self._make_analyzer()

        chain = [
            ChainStep(entity_type="user", entity_id="attacker", entity_name="attacker"),
            ChainStep(entity_type="ip", entity_id="10.0.0.1", entity_name="10.0.0.1"),
        ]
        result = analyzer._enrich_chain_with_ancestry(chain)

        assert len(result) == 2
        assert result[0].entity_type == "user"
        assert result[1].entity_type == "ip"

    @patch("agent.analyzer.llm_analyzer.get_process_chain")
    @patch("agent.analyzer.llm_analyzer.kuzu")
    def test_enrich_preserves_chain_when_kuzu_empty(self, mock_kuzu, mock_get_chain):
        mock_get_chain.return_value = []
        analyzer = self._make_analyzer()

        chain = [
            ChainStep(entity_type="process", entity_id="ssh", entity_name="ssh", pid=300),
        ]
        result = analyzer._enrich_chain_with_ancestry(chain)

        assert len(result) == 1
        assert result[0].entity_name == "ssh"
        assert result[0].pid == 300

    def test_auth_chain_includes_sshd_anchor(self):
        """Auth event chain has: user, sshd (no PID), ip."""
        analyzer = self._make_analyzer()
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="attacker"),
            src_endpoint=NetworkEndpoint(ip="10.0.0.50"),
            device=DeviceInfo(hostname="victim-host"),
        )
        chain = analyzer._build_chain_from_events([(1, event)])

        assert len(chain) == 3
        assert chain[0].entity_type == "user"
        assert chain[0].entity_name == "attacker"
        assert chain[1].entity_type == "process"
        assert chain[1].entity_name == "sshd"
        assert chain[1].pid is None  # forensic integrity — no PID guessing
        assert chain[2].entity_type == "ip"
        assert chain[2].entity_id == "10.0.0.50"

    def test_auth_chain_sshd_anchor_no_src_ip(self):
        """Auth event without src_endpoint has: user, sshd (no PID)."""
        analyzer = self._make_analyzer()
        event = Authentication(
            activity_id=1,
            status_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            user=UserInfo(name="localuser"),
            device=DeviceInfo(hostname="host1"),
        )
        chain = analyzer._build_chain_from_events([(2, event)])

        assert len(chain) == 2
        assert chain[0].entity_type == "user"
        assert chain[0].entity_name == "localuser"
        assert chain[1].entity_type == "process"
        assert chain[1].entity_name == "sshd"
        assert chain[1].pid is None


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

    @staticmethod
    def _phase0_miss():
        """Create a mock result where Phase 0 (persisted Incident lookup) returns None."""
        result = MagicMock()
        result.single.return_value = None
        return result

    @staticmethod
    def _port_extraction_result(iocs_json='{"ports": [22]}'):
        """Mock result for _extract_finding_port session.run call."""
        result = MagicMock()
        record = MagicMock()
        record.__getitem__ = lambda self, k: iocs_json
        result.single.return_value = record
        return result

    def _phase1_record(self, **overrides):
        """Build a mock Phase 1 record with sane defaults.

        Attack-direction semantics:
        - src = finding host (initiator, e.g. SSH client)
        - dst = IP-match host (target, e.g. SSH server)
        - source_chain = chain from the finding (on initiator)
        """
        defaults = {
            "src_agent_id": "agent-source",
            "src_hostname": "source-host",
            "src_ip_addresses": ["10.0.0.10"],
            "finding_id": "f-001",
            "title": "SSH lateral movement",
            "severity": "high",
            "timestamp": 1700000000,
            "description": "Lateral movement via SSH detected",
            "source_chain": [
                {"entity_type": "process", "entity_id": "ssh", "entity_name": "ssh",
                 "pid": 500, "timestamp": 1700000000, "step_index": 0},
                {"entity_type": "process", "entity_id": "bash", "entity_name": "bash",
                 "pid": 501, "timestamp": 1700000001, "step_index": 1},
            ],
            "pivot_ip": "10.0.0.20",
            "dst_agent_id": "agent-target",
            "dst_hostname": "target-host",
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
            {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
             "pid": 100, "timestamp": 1700000000, "step_index": 0},
        ]
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase0_miss(),
            self._phase1_record(),
            phase2a_result,
        ]

        result = client.get_lateral_movement_detail("f-001")

        assert "pivot_ip" in result
        assert result["pivot_ip"] == "10.0.0.20"

    def test_returns_source_and_target_chains(self):
        """Verify separate source_chain and target_chain lists with correct content."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        target_steps = [
            {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
             "pid": 100, "timestamp": 1700000000, "step_index": 0},
            {"entity_type": "process", "entity_id": "zsh", "entity_name": "zsh",
             "pid": 101, "timestamp": 1700000001, "step_index": 1},
        ]
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: target_steps
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase0_miss(),
            self._phase1_record(),
            phase2a_result,
        ]

        result = client.get_lateral_movement_detail("f-001")

        assert "source_chain" in result
        assert "target_chain" in result
        # source_chain comes from Phase 1 (finding's chain on initiator)
        assert len(result["source_chain"]) == 2
        assert result["source_chain"][0]["entity_name"] == "ssh"
        assert result["source_chain"][1]["entity_name"] == "bash"
        # target_chain comes from Phase 2A (finding on target host)
        assert len(result["target_chain"]) == 2
        assert result["target_chain"][0]["entity_name"] == "sshd"
        assert result["target_chain"][1]["entity_name"] == "zsh"
        # Old 'chain' and 'victim_chain' keys should not be present
        assert "chain" not in result
        assert "victim_chain" not in result

    def test_fallback_to_inferred_target_chain(self):
        """Phase 2A returns empty, no settings_db → Phase 2B builds inferred target host+IP chain."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        # Phase 2A returns empty
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase0_miss(),
            self._phase1_record(),
            phase2a_result,
        ]

        result = client.get_lateral_movement_detail("f-001", settings_db=None)

        assert result["target_chain_inferred"] is True
        assert len(result["target_chain"]) == 1
        assert result["target_chain"][0]["entity_type"] == "ip"
        assert result["target_chain"][0]["entity_id"] == "10.0.0.20"

    def test_empty_result_when_finding_not_found(self):
        """Returns {} for nonexistent finding_id."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase1_result = MagicMock()
        phase1_result.single.return_value = None
        mock_session.run.side_effect = [self._phase0_miss(), phase1_result]

        result = client.get_lateral_movement_detail("nonexistent")

        assert result == {}

    def test_query_includes_involves_ip(self):
        """Phase 1 Cypher includes both INVOLVES_IP and entity_type = 'ip'."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase1_result = MagicMock()
        phase1_result.single.return_value = None
        mock_session.run.side_effect = [self._phase0_miss(), phase1_result]

        client.get_lateral_movement_detail("f-check")

        # Phase 1 query should reference both detection paths (index 1 after Phase 0)
        phase1_query = mock_session.run.call_args_list[1][0][0]
        assert "INVOLVES_IP" in phase1_query
        assert "entity_type = 'ip'" in phase1_query


# ── Phase 2B Federated XDR tests ─────────────────────────────────


class TestPhase2BFederatedXDR(TestLateralMovementDetail):
    """Test Phase 2B: target chain via lateral_victim_trace on TARGET agent."""

    def test_phase2b_enqueues_victim_trace_on_target(self):
        """Phase 2A empty → enqueues lateral_victim_trace on TARGET agent for target_chain."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase0_miss(), self._phase1_record(), phase2a_result,
            self._port_extraction_result(),  # _extract_finding_port
        ]

        mock_sdb = MagicMock()
        mock_sdb.get_xdr_result.return_value = None  # No prior query

        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        # Should have enqueued lateral_victim_trace on the TARGET agent
        victim_calls = [
            c for c in mock_sdb.enqueue_xdr_query.call_args_list
            if c[0][3] == "lateral_victim_trace"
        ]
        assert len(victim_calls) == 1
        vc = victim_calls[0]
        assert vc[0][1] == "agent-target"            # target agent
        assert vc[0][3] == "lateral_victim_trace"     # inbound query
        # Params should include victim_ips and target_port
        import json
        params = json.loads(vc[0][4])
        assert "victim_ips" in params
        assert params["victim_ips"] == ["10.0.0.10"]  # source's IP
        assert params["target_port"] == 22
        assert result.get("target_chain_pending") is True

    def test_phase2b_returns_pending_for_active_query(self):
        """get_xdr_result returns pending → target_chain_pending=True."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [self._phase0_miss(), self._phase1_record(), phase2a_result]

        mock_sdb = MagicMock()
        mock_sdb.get_xdr_result.side_effect = lambda fid, qt: (
            {"status": "pending", "result_json": None}
            if qt == "lateral_victim_trace" else None
        )

        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        assert result.get("target_chain_pending") is True

    def test_phase2b_builds_target_chain_from_completed_victim_trace(self):
        """Completed lateral_victim_trace → builds stitched target chain with inbound process."""
        import json
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [self._phase0_miss(), self._phase1_record(), phase2a_result]

        # Target agent's inbound SSH → sshd receiving connection from source IP
        xdr_records = [
            {"process_name": "sshd", "pid": 800, "cmd_line": "/usr/sbin/sshd",
             "from_ip": "10.0.0.10", "dst_port": 22, "timestamp": "2025-06-01",
             "username": "root"},
        ]
        mock_sdb = MagicMock()
        mock_sdb.get_xdr_result.side_effect = lambda fid, qt: (
            {"status": "completed",
             "result_json": json.dumps({"status": "ok", "records": xdr_records})}
            if qt == "lateral_victim_trace" else None
        )

        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        assert result.get("target_chain_xdr_stitched") is True
        tc = result["target_chain"]
        assert len(tc) == 3
        # Reversed: IP → process → user (flow enters from pivot IP)
        assert tc[0]["entity_type"] == "ip"
        assert tc[0]["entity_name"] == "10.0.0.10"  # source IP (entry point)
        assert tc[1]["entity_type"] == "process"
        assert tc[1]["entity_name"] == "sshd"  # sshd SERVER, not ssh client
        assert tc[2]["entity_type"] == "user"
        assert tc[2]["entity_name"] == "root"

    def test_phase2b_inferred_fallback_without_settings_db(self):
        """settings_db=None → falls through to inferred target host chain."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: []
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [self._phase0_miss(), self._phase1_record(), phase2a_result]

        result = client.get_lateral_movement_detail("f-001", settings_db=None)

        assert result.get("target_chain_inferred") is True
        assert "target_chain_pending" not in result
        assert "target_chain_xdr_stitched" not in result


class TestPhase2CSourceChainFederated(TestLateralMovementDetail):
    """Test Phase 2C: source chain federated query via lateral_source_trace on SOURCE agent."""

    def test_phase2c_enqueues_source_trace_when_chain_empty(self):
        """Empty source_chain + pivot_ip → enqueues lateral_source_trace on source agent."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        # Phase 2A returns target chain so Phase 2B is skipped
        target_steps = [
            {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
             "pid": 800, "timestamp": 1700000000, "step_index": 0},
        ]
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: target_steps
        phase2a_result.single.return_value = phase2a_rec

        # Phase 1 record with empty source_chain (no chain data in Neo4j)
        mock_session.run.side_effect = [
            self._phase0_miss(),
            self._phase1_record(source_chain=[]),
            phase2a_result,
            self._port_extraction_result(),  # _extract_finding_port
        ]

        mock_sdb = MagicMock()
        mock_sdb.get_xdr_result.return_value = None  # No prior source query

        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        # Should have enqueued lateral_source_trace for the SOURCE agent
        source_calls = [
            c for c in mock_sdb.enqueue_xdr_query.call_args_list
            if c[0][3] == "lateral_source_trace"
        ]
        assert len(source_calls) == 1
        sc = source_calls[0]
        assert sc[0][1] == "agent-source"           # source agent
        assert sc[0][3] == "lateral_source_trace"    # outbound query
        import json
        params = json.loads(sc[0][4])
        assert "dst_ips" in params
        assert params["dst_ips"] == ["10.0.0.20"]   # pivot IP (target's IP)
        assert params["target_port"] == 22
        assert result.get("source_chain_pending") is True

    def test_phase2c_builds_source_chain_from_completed_result(self):
        """Completed source trace → builds stitched source chain."""
        import json
        client = self._make_client()
        mock_session = self._mock_session(client)

        target_steps = [
            {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
             "pid": 800, "timestamp": 1700000001, "step_index": 0},
        ]
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: target_steps
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [
            self._phase0_miss(),
            self._phase1_record(source_chain=[]),
            phase2a_result,
        ]

        # Source agent's outbound SSH
        source_records = [
            {"process_name": "ssh", "pid": 500, "cmd_line": "ssh thomas@10.0.0.20",
             "from_ip": "10.0.0.20", "dst_port": 22, "timestamp": "2025-06-01",
             "username": "thomas"},
        ]
        mock_sdb = MagicMock()
        mock_sdb.get_xdr_result.side_effect = lambda fid, qt: (
            {"status": "completed",
             "result_json": json.dumps({"status": "ok", "records": source_records})}
            if qt == "lateral_source_trace" else None
        )

        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        assert result.get("source_chain_xdr_stitched") is True
        sc = result["source_chain"]
        assert len(sc) == 3
        # Natural order: user → process → IP (outbound toward target)
        assert sc[0]["entity_type"] == "user"
        assert sc[0]["entity_name"] == "thomas"
        assert sc[1]["entity_type"] == "process"
        assert sc[1]["entity_name"] == "ssh"
        assert sc[2]["entity_type"] == "ip"
        assert sc[2]["entity_name"] == "10.0.0.20"

    def test_phase2c_skipped_when_source_chain_present(self):
        """Phase 2C does nothing when source_chain is already populated from Phase 1."""
        client = self._make_client()
        mock_session = self._mock_session(client)

        target_steps = [
            {"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd",
             "pid": 800, "timestamp": 1700000000, "step_index": 0},
        ]
        phase2a_result = MagicMock()
        phase2a_rec = MagicMock()
        phase2a_rec.__getitem__ = lambda s, k: target_steps
        phase2a_result.single.return_value = phase2a_rec

        mock_session.run.side_effect = [self._phase0_miss(), self._phase1_record(), phase2a_result]

        mock_sdb = MagicMock()
        result = client.get_lateral_movement_detail("f-001", settings_db=mock_sdb)

        # No source trace enqueue since Phase 1 provided the chain
        assert "source_chain_pending" not in result
        assert "source_chain_xdr_stitched" not in result
        # get_xdr_result should not be called for source trace
        source_calls = [
            c for c in mock_sdb.get_xdr_result.call_args_list
            if len(c[0]) > 1 and c[0][1] == "lateral_source_trace"
        ]
        assert len(source_calls) == 0
