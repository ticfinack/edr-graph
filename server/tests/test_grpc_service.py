"""Tests for the FleetServicer gRPC implementation."""

from unittest.mock import MagicMock, patch

from agent.fleet.proto import fleet_pb2
from server.grpc_service import FleetServicer


class TestFleetServicer:
    def _make_servicer(self):
        mock_neo4j = MagicMock()
        return FleetServicer(mock_neo4j), mock_neo4j

    def test_register_agent_success(self):
        servicer, neo4j = self._make_servicer()
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=fleet_pb2.AgentInfo(
                agent_id="agent-001",
                hostname="test-host",
                platform="linux",
                os_version="5.15.0",
                agent_version="0.1.0",
                registered_at=1700000000,
            )
        )
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is True
        assert response.agent_id == "agent-001"
        neo4j.register_agent.assert_called_once()
        call_args = neo4j.register_agent.call_args[0][0]
        assert call_args["hostname"] == "test-host"
        assert call_args["platform"] == "linux"

    def test_register_agent_failure(self):
        servicer, neo4j = self._make_servicer()
        neo4j.register_agent.side_effect = RuntimeError("DB error")
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=fleet_pb2.AgentInfo(
                agent_id="agent-002",
                hostname="fail-host",
            )
        )
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False

    def test_send_findings(self):
        servicer, neo4j = self._make_servicer()
        request = fleet_pb2.SendFindingsRequest(
            agent_id="agent-001",
            findings=[
                fleet_pb2.SecurityFinding(
                    id="finding-001",
                    timestamp=1700000000,
                    severity="high",
                    title="Test finding",
                    description="Test",
                    recommendation="Investigate",
                    iocs_json="{}",
                ),
                fleet_pb2.SecurityFinding(
                    id="finding-002",
                    timestamp=1700000001,
                    severity="medium",
                    title="Another finding",
                    description="Test 2",
                    recommendation="Monitor",
                    iocs_json='{"ips": ["1.2.3.4"]}',
                ),
            ],
        )
        context = MagicMock()
        response = servicer.SendFindings(request, context)

        assert response.accepted_count == 2
        assert neo4j.ingest_finding.call_count == 2

    def test_send_findings_partial_failure(self):
        servicer, neo4j = self._make_servicer()
        neo4j.ingest_finding.side_effect = [None, RuntimeError("fail")]
        request = fleet_pb2.SendFindingsRequest(
            agent_id="agent-001",
            findings=[
                fleet_pb2.SecurityFinding(
                    id="f-ok",
                    timestamp=0,
                    severity="low",
                    title="OK",
                    description="",
                    recommendation="",
                    iocs_json="{}",
                ),
                fleet_pb2.SecurityFinding(
                    id="f-fail",
                    timestamp=0,
                    severity="high",
                    title="Fail",
                    description="",
                    recommendation="",
                    iocs_json="{}",
                ),
            ],
        )
        context = MagicMock()
        response = servicer.SendFindings(request, context)

        assert response.accepted_count == 1

    def test_send_events(self):
        servicer, neo4j = self._make_servicer()
        request = fleet_pb2.SendEventsRequest(
            agent_id="agent-001",
            events=[
                fleet_pb2.OcsfEvent(
                    class_uid=4001,
                    event_json='{"class_uid": 4001, "dst_endpoint": {"ip": "10.0.0.1"}}',
                ),
            ],
        )
        context = MagicMock()
        response = servicer.SendEvents(request, context)

        assert response.accepted_count == 1
        neo4j.ingest_ocsf_event.assert_called_once()

    def test_heartbeat(self):
        servicer, neo4j = self._make_servicer()
        request = fleet_pb2.HeartbeatRequest(
            agent_id="agent-001",
            timestamp=1700000000,
            queue_depth=42,
            findings_count=5,
            status="healthy",
        )
        context = MagicMock()
        response = servicer.Heartbeat(request, context)

        assert response.acknowledged is True
        neo4j.update_heartbeat.assert_called_once_with("agent-001", 1700000000)

    def test_heartbeat_failure(self):
        servicer, neo4j = self._make_servicer()
        neo4j.update_heartbeat.side_effect = RuntimeError("DB error")
        request = fleet_pb2.HeartbeatRequest(
            agent_id="agent-001",
            timestamp=1700000000,
        )
        context = MagicMock()
        response = servicer.Heartbeat(request, context)

        assert response.acknowledged is False
