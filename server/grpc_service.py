"""FleetService gRPC implementation.

Receives agent registrations, findings, OCSF events, and heartbeats
from distributed EDR agents and stores them in Neo4j for cross-host
correlation.
"""

from __future__ import annotations

import json
import logging

import grpc

from agent.fleet.proto import fleet_pb2, fleet_pb2_grpc
from agent.fleet.serializers import proto_to_finding_dict
from server.neo4j_client import Neo4jClient

logger = logging.getLogger("server.grpc")


class FleetServicer(fleet_pb2_grpc.FleetServiceServicer):
    """gRPC service implementation for the central fleet server."""

    def __init__(self, neo4j: Neo4jClient) -> None:
        self._neo4j = neo4j

    def RegisterAgent(self, request, context):
        """Register an agent, store Host node in Neo4j."""
        info = request.agent_info
        agent_data = {
            "agent_id": info.agent_id,
            "hostname": info.hostname,
            "platform": info.platform,
            "os_version": info.os_version,
            "agent_version": info.agent_version,
            "registered_at": info.registered_at,
        }

        try:
            self._neo4j.register_agent(agent_data)
            logger.info("Agent registered: %s (%s)", info.agent_id, info.hostname)
            return fleet_pb2.RegisterAgentResponse(
                accepted=True,
                agent_id=info.agent_id,
                message="registered",
            )
        except Exception:
            logger.exception("Failed to register agent %s", info.agent_id)
            context.set_code(grpc.StatusCode.INTERNAL)
            return fleet_pb2.RegisterAgentResponse(
                accepted=False,
                agent_id=info.agent_id,
                message="registration failed",
            )

    def SendFindings(self, request, context):
        """Ingest findings from an agent into Neo4j."""
        accepted = 0
        for proto_finding in request.findings:
            try:
                finding_dict = proto_to_finding_dict(proto_finding)
                self._neo4j.ingest_finding(request.agent_id, finding_dict)
                accepted += 1
            except Exception:
                logger.exception(
                    "Failed to ingest finding %s from %s",
                    proto_finding.id,
                    request.agent_id,
                )

        logger.info(
            "Ingested %d/%d findings from %s",
            accepted,
            len(request.findings),
            request.agent_id,
        )
        return fleet_pb2.SendFindingsResponse(
            accepted_count=accepted,
            message=f"accepted {accepted}/{len(request.findings)}",
        )

    def SendEvents(self, request, context):
        """Ingest OCSF events from an agent into Neo4j."""
        accepted = 0
        for ocsf_event in request.events:
            try:
                event_data = json.loads(ocsf_event.event_json)
                self._neo4j.ingest_ocsf_event(request.agent_id, event_data)
                accepted += 1
            except Exception:
                logger.debug("Failed to ingest event from %s", request.agent_id, exc_info=True)

        return fleet_pb2.SendEventsResponse(
            accepted_count=accepted,
            message=f"accepted {accepted}/{len(request.events)}",
        )

    def Heartbeat(self, request, context):
        """Update agent heartbeat in Neo4j."""
        try:
            self._neo4j.update_heartbeat(request.agent_id, request.timestamp)
            return fleet_pb2.HeartbeatResponse(acknowledged=True, message="ok")
        except Exception:
            logger.debug("Heartbeat update failed for %s", request.agent_id, exc_info=True)
            return fleet_pb2.HeartbeatResponse(acknowledged=False, message="failed")
