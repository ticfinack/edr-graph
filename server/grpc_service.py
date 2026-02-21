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


def _extract_peer_ip(context) -> str:
    """Extract the client IP from the gRPC peer string (e.g., 'ipv4:10.0.0.1:12345')."""
    try:
        peer = context.peer()
        if peer:
            # Format: "ipv4:host:port" or "ipv6:[host]:port"
            parts = peer.split(":")
            if parts[0] == "ipv4" and len(parts) >= 2:
                return parts[1]
            if parts[0] == "ipv6" and len(parts) >= 2:
                return ":".join(parts[1:-1]).strip("[]")
    except Exception:
        pass
    return ""


class FleetServicer(fleet_pb2_grpc.FleetServiceServicer):
    """gRPC service implementation for the central fleet server."""

    def __init__(self, neo4j: Neo4jClient) -> None:
        self._neo4j = neo4j

    def RegisterAgent(self, request, context):
        """Register an agent, store Host node in Neo4j.

        Requires a valid registration key. Rejects with UNAUTHENTICATED if
        no key is provided, or PERMISSION_DENIED if the key is invalid.
        """
        reg_key = request.registration_key
        if not reg_key:
            context.set_code(grpc.StatusCode.UNAUTHENTICATED)
            context.set_details("registration_key is required")
            return fleet_pb2.RegisterAgentResponse(
                accepted=False,
                agent_id=request.agent_info.agent_id if request.agent_info else "",
                message="registration_key is required",
            )

        valid, reason = self._neo4j.validate_registration_key(reg_key)
        if not valid:
            context.set_code(grpc.StatusCode.PERMISSION_DENIED)
            context.set_details(reason)
            logger.warning(
                "Agent registration rejected (%s): %s from %s",
                reason,
                request.agent_info.agent_id if request.agent_info else "unknown",
                _extract_peer_ip(context),
            )
            return fleet_pb2.RegisterAgentResponse(
                accepted=False,
                agent_id=request.agent_info.agent_id if request.agent_info else "",
                message=reason,
            )

        info = request.agent_info
        grpc_peer_ip = _extract_peer_ip(context)
        agent_data = {
            "agent_id": info.agent_id,
            "hostname": info.hostname,
            "platform": info.platform,
            "os_version": info.os_version,
            "agent_version": info.agent_version,
            "registered_at": info.registered_at,
            "ip_address": info.ip_address or grpc_peer_ip,
            "ip_addresses": list(info.ip_addresses) if info.ip_addresses else [],
            "public_ip": info.public_ip or "",
            "grpc_peer_ip": grpc_peer_ip,
        }

        try:
            self._neo4j.register_agent(agent_data, registration_key=reg_key)
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
        """Update agent heartbeat in Neo4j, including clock offset and IPs."""
        try:
            ip_addresses = list(request.ip_addresses) if request.ip_addresses else None
            public_ip = request.public_ip or None
            self._neo4j.update_heartbeat(
                request.agent_id,
                request.timestamp,
                clock_offset_ms=request.clock_offset_ms,
                ip_addresses=ip_addresses,
                public_ip=public_ip,
            )
            return fleet_pb2.HeartbeatResponse(acknowledged=True, message="ok")
        except Exception:
            logger.debug("Heartbeat update failed for %s", request.agent_id, exc_info=True)
            return fleet_pb2.HeartbeatResponse(acknowledged=False, message="failed")
