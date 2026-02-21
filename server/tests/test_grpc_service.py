"""Tests for the FleetServicer gRPC implementation."""

from unittest.mock import MagicMock, patch

import grpc

from agent.fleet.proto import fleet_pb2
from server.grpc_service import FleetServicer


class TestFleetServicer:
    def _make_servicer(self):
        mock_neo4j = MagicMock()
        return FleetServicer(mock_neo4j), mock_neo4j

    def _make_register_request(self, registration_key="valid-key-abc"):
        return fleet_pb2.RegisterAgentRequest(
            agent_info=fleet_pb2.AgentInfo(
                agent_id="agent-001",
                hostname="test-host",
                platform="linux",
                os_version="5.15.0",
                agent_version="0.1.0",
                registered_at=1700000000,
            ),
            registration_key=registration_key,
        )

    def test_register_agent_success(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (True, "ok")
        request = self._make_register_request()
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is True
        assert response.agent_id == "agent-001"
        neo4j.validate_registration_key.assert_called_once_with("valid-key-abc")
        neo4j.register_agent.assert_called_once()
        call_args = neo4j.register_agent.call_args
        assert call_args[0][0]["hostname"] == "test-host"
        assert call_args[0][0]["platform"] == "linux"
        assert call_args[1]["registration_key"] == "valid-key-abc"

    def test_register_agent_no_key(self):
        servicer, neo4j = self._make_servicer()
        request = self._make_register_request(registration_key="")
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False
        assert "registration_key is required" in response.message
        context.set_code.assert_called_with(grpc.StatusCode.UNAUTHENTICATED)
        neo4j.register_agent.assert_not_called()

    def test_register_agent_invalid_key(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (False, "invalid_key")
        request = self._make_register_request(registration_key="bad-key")
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False
        assert response.message == "invalid_key"
        context.set_code.assert_called_with(grpc.StatusCode.PERMISSION_DENIED)
        neo4j.register_agent.assert_not_called()

    def test_register_agent_revoked_key(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (False, "key_revoked")
        request = self._make_register_request(registration_key="revoked-key")
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False
        assert response.message == "key_revoked"
        context.set_code.assert_called_with(grpc.StatusCode.PERMISSION_DENIED)

    def test_register_agent_expired_key(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (False, "key_expired")
        request = self._make_register_request(registration_key="expired-key")
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False
        assert response.message == "key_expired"

    def test_register_agent_max_uses_exceeded(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (False, "max_uses_exceeded")
        request = self._make_register_request(registration_key="exhausted-key")
        context = MagicMock()
        response = servicer.RegisterAgent(request, context)

        assert response.accepted is False
        assert response.message == "max_uses_exceeded"

    def test_register_agent_failure(self):
        servicer, neo4j = self._make_servicer()
        neo4j.validate_registration_key.return_value = (True, "ok")
        neo4j.register_agent.side_effect = RuntimeError("DB error")
        request = self._make_register_request()
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
        neo4j.update_heartbeat.assert_called_once_with("agent-001", 1700000000, clock_offset_ms=0)

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
