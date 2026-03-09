"""Tests for XDR Orchestrator, inline detection, follow-on tagging,
auto-close TTL, surveillance injection, and forwarder extraction.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

# ── Helpers ──────────────────────────────────────────────────────────


def _make_neo4j_client():
    """Create a Neo4jClient with a mocked driver."""
    from server.neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client._driver = MagicMock()
    return client


def _mock_session(client):
    """Wire up the context manager protocol on client._driver.session()."""
    mock_session = MagicMock()
    client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    client._driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return mock_session


# ── Inline lateral movement detection ────────────────────────────────


class TestInlineDetection:
    """Test check_finding_for_lateral_movement creates incidents."""

    def test_lateral_match_creates_incident(self):
        """Finding with IP matching another host → Incident created."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        # check_finding_for_lateral_movement returns one match
        match_record = MagicMock()
        match_record.__iter__ = MagicMock(return_value=iter([
            {"dst_agent_id": "agent-target", "dst_hostname": "target-host", "pivot_ip": "10.0.0.20"},
        ]))
        session.run.return_value = [
            {"dst_agent_id": "agent-target", "dst_hostname": "target-host", "pivot_ip": "10.0.0.20"},
        ]

        result = client.check_finding_for_lateral_movement("agent-source", "f-001")
        assert len(result) == 1
        assert result[0]["dst_agent_id"] == "agent-target"
        assert result[0]["pivot_ip"] == "10.0.0.20"

    def test_no_match_returns_empty(self):
        """No IP overlap → empty list."""
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value = []

        result = client.check_finding_for_lateral_movement("agent-source", "f-002")
        assert result == []


class TestInlineDedup:
    """Test has_incident_for_finding prevents duplicate incidents."""

    def test_existing_incident_returns_true(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: 1
        session.run.return_value.single.return_value = record

        assert client.has_incident_for_finding("f-001", "10.0.0.20") is True

    def test_no_incident_returns_false(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: 0
        session.run.return_value.single.return_value = record

        assert client.has_incident_for_finding("f-002", "10.0.0.30") is False


# ── Follow-on tagging ────────────────────────────────────────────────


class TestFollowOnTagging:
    """Test check_finding_for_follow_on links findings to active incidents."""

    def test_follow_on_links_to_active_incident(self):
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value = [{"incident_id": "inc-001"}]

        linked = client.check_finding_for_follow_on("agent-target", "f-010")
        assert linked == ["inc-001"]

    def test_no_active_incident_returns_empty(self):
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value = []

        linked = client.check_finding_for_follow_on("agent-unrelated", "f-011")
        assert linked == []


# ── Incident CRUD ────────────────────────────────────────────────────


class TestIncidentCRUD:
    """Test create_incident and get_incidents_by_status."""

    def test_create_incident_calls_session_run(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        client.create_incident(
            incident_id="inc-001",
            finding_id="f-001",
            src_agent_id="agent-source",
            dst_agent_id="agent-target",
            pivot_ip="10.0.0.20",
        )

        assert session.run.called
        query = session.run.call_args[0][0]
        assert "Incident" in query
        assert "SOURCE_FINDING" in query
        assert "INVOLVES_HOST" in query
        assert "PIVOT_VIA" in query

    def test_get_incidents_by_status(self):
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value = [
            {
                "incident_id": "inc-001", "incident_type": "lateral_movement",
                "status": "detected", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20", "created_at": 1000, "updated_at": 1000,
            },
        ]

        result = client.get_incidents_by_status("detected")
        assert len(result) == 1
        assert result[0]["incident_id"] == "inc-001"

    def test_update_incident_status(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        client.update_incident_status("inc-001", "sweeping")
        query = session.run.call_args[0][0]
        assert "status" in query
        params = session.run.call_args[0][1]
        assert params["new_status"] == "sweeping"


# ── XDR Orchestrator state machine ───────────────────────────────────


class TestXdrOrchestrator:
    """Test orchestrator state transitions."""

    def _make_orchestrator(self, neo4j=None, settings_db=None, **kwargs):
        from server.xdr_orchestrator import XdrOrchestrator

        return XdrOrchestrator(
            neo4j or MagicMock(),
            settings_db or MagicMock(),
            poll_interval=1,
            query_timeout=kwargs.get("query_timeout", 300),
            auto_close_hours=kwargs.get("auto_close_hours", 48),
        )

    def test_detected_to_sweeping(self):
        """Detected incidents get XDR queries enqueued and transition to sweeping."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-001", "src_agent_id": "agent-src",
                "dst_agent_id": "agent-dst", "pivot_ip": "10.0.0.20",
                "created_at": int(time.time()), "updated_at": int(time.time()),
            },
        ] if s == "detected" else []
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_detected()

        # Should enqueue 4 XDR queries (victim + source + 2 OCSF pulls)
        assert sdb.enqueue_xdr_query.call_count == 4
        qtypes = [c[0][3] for c in sdb.enqueue_xdr_query.call_args_list]
        assert "lateral_victim_trace" in qtypes
        assert "lateral_source_trace" in qtypes
        assert qtypes.count("pull_ocsf_ledger") == 2

        # Victim trace on TARGET agent
        victim_call = [c for c in sdb.enqueue_xdr_query.call_args_list if c[0][3] == "lateral_victim_trace"][0]
        assert victim_call[0][1] == "agent-dst"

        # Source trace on SOURCE agent
        source_call = [c for c in sdb.enqueue_xdr_query.call_args_list if c[0][3] == "lateral_source_trace"][0]
        assert source_call[0][1] == "agent-src"

        # Transition to sweeping
        neo4j.update_incident_status.assert_called_with("inc-001", "sweeping")

    def test_sweeping_to_active_on_completion(self):
        """Completed XDR queries → chains persisted, transition to active."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-002", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20", "created_at": int(time.time()),
                "updated_at": int(time.time()),
            },
        ] if s == "sweeping" else []

        victim_records = [
            {"process_name": "sshd", "pid": 800, "from_ip": "10.0.0.10", "username": "root"},
        ]
        source_records = [
            {"process_name": "ssh", "pid": 500, "from_ip": "10.0.0.20", "username": "attacker"},
        ]

        def get_xdr_result(fid, qt):
            if qt == "lateral_victim_trace":
                return {"status": "completed", "result_json": json.dumps({"records": victim_records})}
            if qt == "lateral_source_trace":
                return {"status": "completed", "result_json": json.dumps({"records": source_records})}
            return None

        sdb.get_xdr_result.side_effect = get_xdr_result

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_sweeping()

        # Incident-level chains are NOT synthesized from flat XDR records
        # (per-finding chains are the authoritative chain data)
        neo4j.persist_incident_chains.assert_not_called()
        neo4j.update_incident_status.assert_called_with("inc-002", "active")

    def test_sweeping_to_active_on_timeout(self):
        """Timed out XDR queries still transition to active."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-003", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20",
                "created_at": int(time.time()) - 600,  # 10 min ago
                "updated_at": int(time.time()) - 600,
            },
        ] if s == "sweeping" else []

        sdb.get_xdr_result.return_value = {"status": "pending", "result_json": None}

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb, query_timeout=300)
        orch._process_sweeping()

        neo4j.update_incident_status.assert_called_with("inc-003", "active")

    def test_auto_close_ttl(self):
        """Active incident with stale updated_at transitions to closed."""
        neo4j = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-004", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20",
                "created_at": int(time.time()) - 200000,
                "updated_at": int(time.time()) - 200000,  # ~55 hours ago
            },
        ] if s == "active" else []

        orch = self._make_orchestrator(neo4j=neo4j, auto_close_hours=48)
        orch._process_active()

        neo4j.update_incident_status.assert_called_with("inc-004", "closed")

    def test_active_not_closed_when_recent(self):
        """Active incident with recent updated_at stays active."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-005", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20",
                "created_at": int(time.time()) - 3600,
                "updated_at": int(time.time()) - 60,  # 1 min ago
            },
        ] if s == "active" else []
        # Mock surveillance pull state so orchestrator can proceed
        sdb.get_surveillance_pull_state.return_value = {"last_enqueue_at": 0, "last_record_ts": 0.0}
        sdb.has_pending_xdr_query.return_value = False
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]
        neo4j.get_incident_chain_pids.return_value = ([500], [800])
        neo4j.get_incident_chain_usernames.return_value = (["attacker"], ["root"])

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb, auto_close_hours=48)
        orch._process_active()

        neo4j.update_incident_status.assert_not_called()


# ── Port correlation ──────────────────────────────────────────────────


class TestPortCorrelation:
    """Test that port data flows through the XDR pipeline."""

    def _make_orchestrator(self, neo4j=None, settings_db=None, **kwargs):
        from server.xdr_orchestrator import XdrOrchestrator

        return XdrOrchestrator(
            neo4j or MagicMock(),
            settings_db or MagicMock(),
            poll_interval=1,
            query_timeout=kwargs.get("query_timeout", 300),
            auto_close_hours=kwargs.get("auto_close_hours", 48),
        )

    def test_detected_passes_port_in_xdr_params(self):
        """Incident with finding that has ports: [22] in IOCs → XDR query params include target_port: 22."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-port-1", "src_agent_id": "agent-src",
                "dst_agent_id": "agent-dst", "pivot_ip": "10.0.0.20",
                "dst_port": 22, "finding_id": "f-port-1",
                "created_at": int(time.time()), "updated_at": int(time.time()),
            },
        ] if s == "detected" else []
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_detected()

        # 4 queries: victim + source + 2 OCSF pulls
        assert sdb.enqueue_xdr_query.call_count == 4

        # Check victim trace params include target_port
        victim_call = [c for c in sdb.enqueue_xdr_query.call_args_list
                       if c[0][3] == "lateral_victim_trace"][0]
        victim_params = json.loads(victim_call[0][4])
        assert victim_params["target_port"] == 22

        # Check source trace params include target_port
        source_call = [c for c in sdb.enqueue_xdr_query.call_args_list
                       if c[0][3] == "lateral_source_trace"][0]
        source_params = json.loads(source_call[0][4])
        assert source_params["target_port"] == 22

    def test_detected_passes_null_port_when_no_ports(self):
        """Finding without ports in IOCs → params include target_port: null."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.side_effect = lambda s: [
            {
                "incident_id": "inc-port-2", "src_agent_id": "agent-src",
                "dst_agent_id": "agent-dst", "pivot_ip": "10.0.0.20",
                "dst_port": None, "finding_id": "f-port-2",
                "created_at": int(time.time()), "updated_at": int(time.time()),
            },
        ] if s == "detected" else []
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]
        neo4j.extract_finding_port.return_value = None

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_detected()

        victim_call = [c for c in sdb.enqueue_xdr_query.call_args_list
                       if c[0][3] == "lateral_victim_trace"][0]
        victim_params = json.loads(victim_call[0][4])
        assert victim_params["target_port"] is None

    def test_create_incident_stores_dst_port(self):
        """create_incident(dst_port=22) stores port on Incident node."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        client.create_incident(
            incident_id="inc-port-3",
            finding_id="f-port-3",
            src_agent_id="agent-src",
            dst_agent_id="agent-dst",
            pivot_ip="10.0.0.20",
            dst_port=22,
        )

        assert session.run.called
        query = session.run.call_args[0][0]
        assert "dst_port" in query
        params = session.run.call_args[0][1]
        assert params["dst_port"] == 22

    def test_get_incidents_returns_port_and_finding_id(self):
        """get_incidents_by_status returns dst_port and finding_id."""
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value = [
            {
                "incident_id": "inc-port-4", "incident_type": "lateral_movement",
                "status": "detected", "src_agent_id": "a1", "dst_agent_id": "a2",
                "pivot_ip": "10.0.0.20", "dst_port": 22, "finding_id": "f-port-4",
                "created_at": 1000, "updated_at": 1000,
            },
        ]

        result = client.get_incidents_by_status("detected")
        assert result[0]["dst_port"] == 22
        assert result[0]["finding_id"] == "f-port-4"

    def test_extract_finding_port_parses_iocs(self):
        """extract_finding_port extracts port from finding IOCs JSON."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: json.dumps({"ips": ["10.0.0.5"], "ports": [22, 443]})
        session.run.return_value.single.return_value = record

        port = client.extract_finding_port("f-port-5")
        assert port == 22

    def test_extract_finding_port_returns_none_when_no_ports(self):
        """extract_finding_port returns None when IOCs have no ports."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: json.dumps({"ips": ["10.0.0.5"]})
        session.run.return_value.single.return_value = record

        port = client.extract_finding_port("f-port-6")
        assert port is None

    def test_grpc_send_findings_passes_port(self):
        """SendFindings inline detection extracts port and passes to create_incident."""
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.check_finding_for_lateral_movement.return_value = [
            {"dst_agent_id": "agent-target", "dst_hostname": "target-host", "pivot_ip": "10.0.0.20"},
        ]
        neo4j.find_active_campaign.return_value = None
        neo4j.has_incident_for_finding.return_value = False
        neo4j.check_finding_for_follow_on.return_value = []
        neo4j.extract_finding_port.return_value = 22

        servicer = FleetServicer(neo4j, settings_db=sdb)

        proto_finding = MagicMock()
        proto_finding.id = "f-port-7"
        proto_finding.severity = "high"
        request = MagicMock()
        request.agent_id = "agent-source"
        request.findings = [proto_finding]
        context = MagicMock()

        with patch("server.grpc_service.proto_to_finding_dict", return_value={
            "id": "f-port-7", "timestamp": 1000, "severity": "high",
            "title": "test", "description": "", "recommendation": "",
            "iocs": {"ports": [22]},
        }):
            servicer.SendFindings(request, context)

        neo4j.create_incident.assert_called_once()
        call_kwargs = neo4j.create_incident.call_args[1]
        assert call_kwargs["dst_port"] == 22


# ── Surveillance targets ─────────────────────────────────────────────


class TestSurveillanceTargets:
    """Test get_surveillance_targets aggregation."""

    def test_aggregates_pivot_ips_and_users(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: {
            "ips": ["10.0.0.20", "10.0.0.30"],
            "users": ["root", "attacker"],
        }[k]
        session.run.return_value.single.return_value = record

        result = client.get_surveillance_targets("agent-target")
        assert "ips" in result
        assert "10.0.0.20" in result["ips"]
        assert "users" in result

    def test_empty_when_no_active_incidents(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: {"ips": [], "users": []}[k]
        session.run.return_value.single.return_value = record

        result = client.get_surveillance_targets("agent-unrelated")
        assert result == {}


# ── Surveillance injection in Heartbeat ──────────────────────────────


class TestSurveillanceInjection:
    """Test Heartbeat config includes active_surveillance for involved agents."""

    def test_heartbeat_includes_surveillance(self):
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_surveillance_targets.return_value = {"ips": ["10.0.0.20"], "users": ["root"]}
        sdb.get_agent_key.return_value = "test-key-123"
        sdb.resolve_agent_config.return_value = {"response_mode": "learning"}
        sdb.get_pending_queries_for_agent.return_value = []

        servicer = FleetServicer(neo4j, settings_db=sdb)

        request = MagicMock()
        request.agent_id = "agent-001"
        request.timestamp = int(time.time())
        request.clock_offset_ms = 0
        request.ip_addresses = ["10.0.0.10"]
        request.public_ip = "1.2.3.4"
        request.query_results_json = ""
        context = MagicMock()

        response = servicer.Heartbeat(request, context)

        assert response.acknowledged is True
        config = json.loads(response.config_json)
        assert "active_surveillance" in config
        assert config["active_surveillance"]["ips"] == ["10.0.0.20"]

    def test_heartbeat_no_surveillance_when_empty(self):
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_surveillance_targets.return_value = {}
        sdb.get_agent_key.return_value = "test-key-123"
        sdb.resolve_agent_config.return_value = {"response_mode": "learning"}
        sdb.get_pending_queries_for_agent.return_value = []

        servicer = FleetServicer(neo4j, settings_db=sdb)

        request = MagicMock()
        request.agent_id = "agent-002"
        request.timestamp = int(time.time())
        request.clock_offset_ms = 0
        request.ip_addresses = ["10.0.0.10"]
        request.public_ip = ""
        request.query_results_json = ""
        context = MagicMock()

        response = servicer.Heartbeat(request, context)

        config = json.loads(response.config_json)
        assert "active_surveillance" not in config


# ── Forwarder surveillance extraction ────────────────────────────────


class TestForwarderSurveillance:
    """Test agent forwarder stores surveillance targets in thread-safe attribute."""

    def _make_forwarder(self):
        from agent.fleet.forwarder import FleetForwarder

        fwd = FleetForwarder.__new__(FleetForwarder)
        fwd._settings = MagicMock()
        fwd._settings.fleet_registration_key = "test-key"
        fwd._agent_id = "agent-001"
        fwd._surveillance_lock = __import__("threading").Lock()
        fwd._surveillance_targets = {}
        fwd._pending_results = []
        fwd._query_executor = None
        return fwd

    def test_surveillance_extracted_from_config(self):
        fwd = self._make_forwarder()

        config = {
            "response_mode": "learning",
            "active_surveillance": {"ips": ["10.0.0.20"], "users": ["root"]},
        }
        config_json = json.dumps(config)

        # Mock signature verification to pass
        with patch.object(fwd, "_verify_config_signature", return_value=True):
            fwd._apply_config_overrides(config_json, "valid-sig")

        assert fwd.surveillance_targets == {"ips": ["10.0.0.20"], "users": ["root"]}

    def test_surveillance_cleared_when_absent(self):
        fwd = self._make_forwarder()
        # Pre-populate
        with fwd._surveillance_lock:
            fwd._surveillance_targets = {"ips": ["old"], "users": []}

        config = {"response_mode": "learning"}
        config_json = json.dumps(config)

        with patch.object(fwd, "_verify_config_signature", return_value=True):
            fwd._apply_config_overrides(config_json, "valid-sig")

        assert fwd.surveillance_targets == {}

    def test_surveillance_property_is_thread_safe_copy(self):
        fwd = self._make_forwarder()
        with fwd._surveillance_lock:
            fwd._surveillance_targets = {"ips": ["10.0.0.20"], "users": ["root"]}

        targets = fwd.surveillance_targets
        targets["ips"].append("INJECTED")

        # Original should not be modified
        assert "INJECTED" not in fwd.surveillance_targets["ips"]


# ── SendFindings inline detection integration ────────────────────────


class TestSendFindingsInlineDetection:
    """Test that SendFindings triggers inline lateral-movement and follow-on checks."""

    def test_creates_incident_on_lateral_match(self):
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.check_finding_for_lateral_movement.return_value = [
            {"dst_agent_id": "agent-target", "dst_hostname": "target-host", "pivot_ip": "10.0.0.20"},
        ]
        neo4j.has_incident_for_finding.return_value = False
        neo4j.find_active_campaign.return_value = None
        neo4j.check_finding_for_follow_on.return_value = []

        servicer = FleetServicer(neo4j, settings_db=sdb)

        proto_finding = MagicMock()
        proto_finding.id = "f-001"
        proto_finding.severity = "high"
        request = MagicMock()
        request.agent_id = "agent-source"
        request.findings = [proto_finding]
        context = MagicMock()

        # Mock proto_to_finding_dict to avoid proto dependency
        with patch("server.grpc_service.proto_to_finding_dict", return_value={"id": "f-001", "timestamp": 1000, "severity": "high", "title": "test", "description": "", "recommendation": "", "iocs": {}}):
            servicer.SendFindings(request, context)

        neo4j.create_incident.assert_called_once()
        call_kwargs = neo4j.create_incident.call_args
        assert call_kwargs[1]["finding_id"] == "f-001"
        assert call_kwargs[1]["dst_agent_id"] == "agent-target"
        assert call_kwargs[1]["pivot_ip"] == "10.0.0.20"

    def test_dedup_skips_existing_incident(self):
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.check_finding_for_lateral_movement.return_value = [
            {"dst_agent_id": "agent-target", "dst_hostname": "target-host", "pivot_ip": "10.0.0.20"},
        ]
        neo4j.has_incident_for_finding.return_value = True  # Already exists
        neo4j.check_finding_for_follow_on.return_value = []

        servicer = FleetServicer(neo4j, settings_db=sdb)

        proto_finding = MagicMock()
        proto_finding.id = "f-001"
        proto_finding.severity = "high"
        request = MagicMock()
        request.agent_id = "agent-source"
        request.findings = [proto_finding]
        context = MagicMock()

        with patch("server.grpc_service.proto_to_finding_dict", return_value={"id": "f-001", "timestamp": 1000, "severity": "high", "title": "test", "description": "", "recommendation": "", "iocs": {}}):
            servicer.SendFindings(request, context)

        neo4j.create_incident.assert_not_called()

    def test_follow_on_linked_in_send_findings(self):
        from server.grpc_service import FleetServicer

        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.check_finding_for_lateral_movement.return_value = []
        neo4j.check_finding_for_follow_on.return_value = ["inc-001"]

        servicer = FleetServicer(neo4j, settings_db=sdb)

        proto_finding = MagicMock()
        proto_finding.id = "f-010"
        proto_finding.severity = "medium"
        request = MagicMock()
        request.agent_id = "agent-target"
        request.findings = [proto_finding]
        context = MagicMock()

        with patch("server.grpc_service.proto_to_finding_dict", return_value={"id": "f-010", "timestamp": 1000, "severity": "medium", "title": "follow-on", "description": "", "recommendation": "", "iocs": {}}):
            servicer.SendFindings(request, context)

        neo4j.check_finding_for_follow_on.assert_called_with("agent-target", "f-010")


# ── Phase 0 in get_lateral_movement_detail ───────────────────────────


class TestPhase0PersistedIncident:
    """Test Phase 0: persisted Incident chains returned instantly."""

    def test_phase0_returns_persisted_chains(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        # Phase 0 returns a result (incident with persisted chains)

        class DictableRecord:
            def __init__(self, data):
                self._data = data
            def __getitem__(self, key):
                return self._data[key]
            def keys(self):
                return self._data.keys()
            def values(self):
                return self._data.values()
            def items(self):
                return self._data.items()
            def get(self, key, default=None):
                return self._data.get(key, default)

        p0_data = {
            "incident_id": "inc-001",
            "src_agent_id": "agent-src",
            "src_hostname": "src-host",
            "dst_agent_id": "agent-dst",
            "dst_hostname": "dst-host",
            "pivot_ip": "10.0.0.20",
            "finding_id": "f-001",
            "title": "SSH lateral",
            "severity": "high",
            "timestamp": 1700000000,
            "description": "test",
            "source_chain": [{"entity_type": "process", "entity_id": "ssh", "entity_name": "ssh", "pid": 500, "timestamp": 0, "step_index": 0}],
            "target_chain": [{"entity_type": "process", "entity_id": "sshd", "entity_name": "sshd", "pid": 800, "timestamp": 0, "step_index": 0}],
        }
        p0_result = MagicMock()
        p0_result.single.return_value = DictableRecord(p0_data)

        session.run.side_effect = [p0_result]

        result = client.get_lateral_movement_detail("f-001")

        assert result.get("incident_chains_persisted") is True
        assert len(result["source_chain"]) == 1
        assert len(result["target_chain"]) == 1
        assert result["source_chain"][0]["entity_name"] == "ssh"
        assert result["target_chain"][0]["entity_name"] == "sshd"
        # Only Phase 0 query should have been called (no Phase 1)
        assert session.run.call_count == 1

    def test_phase0_miss_falls_through_to_phase1(self):
        """When Phase 0 returns no result, Phase 1 executes."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        # Phase 0 returns nothing
        p0_result = MagicMock()
        p0_result.single.return_value = None

        # Phase 1 also returns nothing
        p1_result = MagicMock()
        p1_result.single.return_value = None

        session.run.side_effect = [p0_result, p1_result]

        result = client.get_lateral_movement_detail("f-no-match")

        assert result == {}
        # Both Phase 0 and Phase 1 queries should have been called
        assert session.run.call_count == 2


# ── Autonomous surveillance pulls ─────────────────────────────────────


class TestAutonomousSurveillance:
    """Test orchestrator autonomous surveillance pull enqueue logic."""

    def _make_orchestrator(self, neo4j=None, settings_db=None, **kwargs):
        from server.xdr_orchestrator import XdrOrchestrator

        return XdrOrchestrator(
            neo4j or MagicMock(),
            settings_db or MagicMock(),
            poll_interval=1,
            query_timeout=kwargs.get("query_timeout", 300),
            auto_close_hours=kwargs.get("auto_close_hours", 48),
        )

    def _active_incident(self, incident_id="inc-surv-1", **overrides):
        base = {
            "incident_id": incident_id,
            "src_agent_id": "agent-src",
            "dst_agent_id": "agent-dst",
            "pivot_ip": "10.0.0.20",
            "created_at": int(time.time()) - 3600,
            "updated_at": int(time.time()) - 60,
        }
        base.update(overrides)
        return base

    def test_process_active_enqueues_surveillance_pull(self):
        """Active incident triggers enqueue for both sides with PIDs + usernames."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.return_value = [self._active_incident()]
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]
        neo4j.get_incident_chain_pids.return_value = ([500], [800])
        neo4j.get_incident_chain_usernames.return_value = (["attacker"], ["root"])
        sdb.get_surveillance_pull_state.return_value = {"last_enqueue_at": 0, "last_record_ts": 0.0}
        sdb.has_pending_xdr_query.return_value = False

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_active()

        # Should enqueue 2 surveillance queries (dst + src)
        assert sdb.enqueue_xdr_query.call_count == 2
        finding_ids = [c[0][2] for c in sdb.enqueue_xdr_query.call_args_list]
        assert "inc-surv-1:surv_dst" in finding_ids
        assert "inc-surv-1:surv_src" in finding_ids

        # Verify params include anchor_pids AND usernames
        for call in sdb.enqueue_xdr_query.call_args_list:
            params = json.loads(call[0][4])
            assert "anchor_pids" in params
            assert "usernames" in params

        # Both sides should have pull state updated
        assert sdb.set_surveillance_pull_state.call_count == 2

    def test_process_active_respects_60s_cadence(self):
        """No enqueue if last pull < 60s ago."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.return_value = [self._active_incident()]
        neo4j.get_incident_chain_pids.return_value = ([500], [800])
        # Last enqueue 30s ago — too recent
        sdb.get_surveillance_pull_state.return_value = {
            "last_enqueue_at": int(time.time()) - 30, "last_record_ts": 0.0,
        }

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_active()

        sdb.enqueue_xdr_query.assert_not_called()

    def test_process_active_passes_since_param(self):
        """since param set from last_record_ts."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.return_value = [self._active_incident()]
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]
        neo4j.get_incident_chain_pids.return_value = ([500], [800])
        neo4j.get_incident_chain_usernames.return_value = (["attacker"], ["root"])
        sdb.get_surveillance_pull_state.return_value = {
            "last_enqueue_at": 0, "last_record_ts": 1700000000.0,
        }
        sdb.has_pending_xdr_query.return_value = False

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_active()

        assert sdb.enqueue_xdr_query.call_count == 2
        for call in sdb.enqueue_xdr_query.call_args_list:
            params = json.loads(call[0][4])
            assert params["since"] == 1700000000.0

    def test_process_active_skips_pending_query(self):
        """No duplicate enqueue if query already pending."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.return_value = [self._active_incident()]
        neo4j.get_incident_src_ips.return_value = ["10.0.0.10"]
        neo4j.get_incident_chain_pids.return_value = ([500], [800])
        neo4j.get_incident_chain_usernames.return_value = (["attacker"], ["root"])
        sdb.get_surveillance_pull_state.return_value = {"last_enqueue_at": 0, "last_record_ts": 0.0}
        sdb.has_pending_xdr_query.return_value = True  # Already pending

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_active()

        sdb.enqueue_xdr_query.assert_not_called()

    def test_process_active_auto_close_skips_surveillance(self):
        """Stale incident gets closed, not pulled."""
        neo4j = MagicMock()
        sdb = MagicMock()

        stale = self._active_incident(
            updated_at=int(time.time()) - 200000,  # ~55 hours ago
        )
        neo4j.get_incidents_by_status.return_value = [stale]

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb, auto_close_hours=48)
        orch._process_active()

        neo4j.update_incident_status.assert_called_with("inc-surv-1", "closed")
        sdb.enqueue_xdr_query.assert_not_called()

    def test_active_does_not_synthesize_incident_chains(self):
        """Active processing does not create incident-level chains (per-finding chains are authoritative)."""
        neo4j = MagicMock()
        sdb = MagicMock()

        neo4j.get_incidents_by_status.return_value = [self._active_incident()]
        neo4j.get_incident_chain_pids.return_value = ([], [])
        sdb.get_surveillance_pull_state.return_value = {
            "last_enqueue_at": int(time.time()) - 30, "last_record_ts": 0.0,
        }

        orch = self._make_orchestrator(neo4j=neo4j, settings_db=sdb)
        orch._process_active()

        neo4j.persist_incident_chains.assert_not_called()
