"""FleetService gRPC implementation.

Receives agent registrations, findings, OCSF events, and heartbeats
from distributed EDR agents and stores them in Neo4j for cross-host
correlation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid

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

    def __init__(self, neo4j: Neo4jClient, settings_db=None) -> None:
        self._neo4j = neo4j
        self._settings_db = settings_db

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

        # Check if this is a re-registration (same agent_id + same key).
        # If so, skip validate_registration_key to avoid incrementing use_count.
        # Note: re-registration detection requires settings_db (agent_key_map
        # lives in SQLite). Neo4j-only mode always uses the increment path.
        agent_id = request.agent_info.agent_id if request.agent_info else ""
        is_reregistration = False
        if agent_id and self._settings_db:
            existing_key = self._settings_db.get_agent_key(agent_id)
            if existing_key is not None and existing_key == reg_key:
                is_reregistration = True

        if is_reregistration:
            # Re-registration: verify key isn't revoked/expired, don't increment use_count.
            # is_reregistration is only True when self._settings_db is set (guarded above).
            valid, reason = self._settings_db.check_key_status(reg_key)
        elif self._settings_db:
            valid, reason = self._settings_db.validate_registration_key(reg_key)
        else:
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
            # Store agent→key mapping for HMAC config signing
            if self._settings_db:
                self._settings_db.set_agent_key(info.agent_id, reg_key)
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

        # Inline lateral movement detection + follow-on tagging + campaign grouping
        # Only medium+ findings participate in incident creation / campaign grouping
        # to avoid polluting incidents with info/low noise.
        _INCIDENT_SEVERITIES = {"medium", "high", "critical"}
        for proto_finding in request.findings:
            try:
                fid = proto_finding.id
                sev = (proto_finding.severity or "").lower()

                # 1. Follow-on check: link to active incidents targeting this agent
                # (severity filter is enforced in the Cypher query)
                linked = self._neo4j.check_finding_for_follow_on(request.agent_id, fid)
                if linked:
                    logger.info("Finding %s linked as follow-on to incidents: %s", fid, linked)

                # Skip campaign grouping / incident creation for low-signal findings
                if sev not in _INCIDENT_SEVERITIES:
                    continue

                # 2. Lateral movement check with campaign grouping
                matches = self._neo4j.check_finding_for_lateral_movement(request.agent_id, fid)
                for m in matches:
                    existing = self._neo4j.find_active_campaign(
                        agent_ids=[request.agent_id, m["dst_agent_id"]],
                        ips=[m["pivot_ip"]],
                        window_hours=12,
                    )
                    if existing:
                        self._neo4j.append_finding_to_incident(
                            existing, fid, request.agent_id, m["dst_agent_id"], m["pivot_ip"],
                        )
                        logger.info("Finding %s appended to campaign %s", fid, existing)
                    elif not self._neo4j.has_incident_for_finding(fid, m["pivot_ip"]):
                        incident_id = str(uuid.uuid4())
                        port = self._neo4j.extract_finding_port(fid)
                        self._neo4j.create_incident(
                            incident_id=incident_id,
                            finding_id=fid,
                            src_agent_id=request.agent_id,
                            dst_agent_id=m["dst_agent_id"],
                            pivot_ip=m["pivot_ip"],
                            dst_port=port,
                        )

                # 3. Vertical movement check (privilege escalation on same host)
                if not matches:
                    vert = self._neo4j.check_finding_for_vertical_movement(request.agent_id, fid)
                    for v in vert:
                        existing = self._neo4j.find_active_campaign(
                            agent_ids=[request.agent_id],
                            ips=[],
                            window_hours=12,
                        )
                        if existing:
                            self._neo4j.append_finding_to_incident(
                                existing, fid, request.agent_id, request.agent_id, "",
                            )
                            logger.info("Vertical finding %s appended to campaign %s", fid, existing)
                        else:
                            incident_id = str(uuid.uuid4())
                            self._neo4j.create_incident(
                                incident_id=incident_id,
                                finding_id=fid,
                                src_agent_id=request.agent_id,
                                dst_agent_id=request.agent_id,
                                pivot_ip="",
                            )
                            # Override incident_type for vertical movement
                            self._neo4j.update_incident_status(incident_id, "detected")
                            with self._neo4j._driver.session() as session:
                                session.run(
                                    "MATCH (inc:Incident {incident_id: $iid}) "
                                    "SET inc.incident_type = 'vertical_movement'",
                                    {"iid": incident_id},
                                )
                            logger.info(
                                "Created vertical movement incident %s for %s (%s → %s)",
                                incident_id, fid, v.get("original_user"), v.get("escalated_user"),
                            )
                        break  # One vertical incident per finding is enough
            except Exception:
                logger.debug(
                    "Inline detection failed for finding %s", proto_finding.id, exc_info=True,
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

    def _ingest_surveillance_logs(self, query_meta: dict, result: dict) -> None:
        """Parse surveillance query results into the persistent table."""
        finding_id = query_meta.get("finding_id", "")
        agent_id = query_meta.get("agent_id", "")

        # Extract incident_id and side from finding_id like "inc-id:surv_dst"
        incident_id = ""
        side = ""
        if ":surv_dst" in finding_id:
            incident_id = finding_id.split(":surv_dst")[0]
            side = "dst"
        elif ":surv_src" in finding_id:
            incident_id = finding_id.split(":surv_src")[0]
            side = "src"

        if not incident_id or not side:
            return

        records = result.get("records", []) if isinstance(result, dict) else []
        if not records:
            return

        self._settings_db.upsert_surveillance_logs(incident_id, agent_id, side, records)

        # Update pull state with max timestamp from ingested records
        max_ts = max((r.get("timestamp", 0) for r in records), default=0)
        if max_ts > 0:
            self._settings_db.set_surveillance_pull_state(
                incident_id, side, last_record_ts=max_ts,
            )

        logger.debug(
            "Ingested %d surveillance records for %s side=%s",
            len(records), incident_id, side,
        )

    def _ingest_ocsf_evidence(self, query_meta: dict, result: dict) -> None:
        """Parse OCSF ledger query results into the persistent evidence table."""
        finding_id = query_meta.get("finding_id", "")
        agent_id = query_meta.get("agent_id", "")

        # Extract incident_id from finding_id like "inc-id:ocsf_dst"
        incident_id = ""
        if ":ocsf_dst" in finding_id:
            incident_id = finding_id.split(":ocsf_dst")[0]
        elif ":ocsf_src" in finding_id:
            incident_id = finding_id.split(":ocsf_src")[0]

        if not incident_id:
            return

        records = result.get("records", []) if isinstance(result, dict) else []
        if not records:
            return

        inserted = self._settings_db.upsert_ocsf_evidence(incident_id, agent_id, records)
        logger.debug(
            "Ingested %d OCSF evidence records for %s (new=%d)",
            len(records), incident_id, inserted,
        )

    def Heartbeat(self, request, context):
        """Update agent heartbeat in Neo4j, including clock offset and IPs."""
        # Verify agent is registered before processing
        agent_key = None
        if self._settings_db:
            agent_key = self._settings_db.get_agent_key(request.agent_id)
        if not agent_key:
            return fleet_pb2.HeartbeatResponse(acknowledged=False, message="unregistered")

        # Receive federated query results from agent
        if request.query_results_json and self._settings_db:
            try:
                results = json.loads(request.query_results_json)
                for r in results:
                    query_meta = self._settings_db.complete_xdr_query(
                        r["query_id"], json.dumps(r.get("result", {}))
                    )
                    if query_meta and query_meta["query_type"] == "pull_surveillance_logs":
                        self._ingest_surveillance_logs(query_meta, r.get("result", {}))
                    elif query_meta and query_meta["query_type"] == "pull_ocsf_ledger":
                        self._ingest_ocsf_evidence(query_meta, r.get("result", {}))
            except (json.JSONDecodeError, KeyError, TypeError):
                logger.debug("Bad query_results_json from %s", request.agent_id)

        try:
            ip_addresses = list(request.ip_addresses) if request.ip_addresses else None
            public_ip = request.public_ip or None
            ioc_stats_json = request.ioc_stats_json or None
            self._neo4j.update_heartbeat(
                request.agent_id,
                request.timestamp,
                clock_offset_ms=request.clock_offset_ms,
                ip_addresses=ip_addresses,
                public_ip=public_ip,
                ioc_stats_json=ioc_stats_json,
            )

            # Send agent config defaults + pending queries, signed with per-agent derived HMAC key
            config_json = ""
            config_signature = ""
            if self._settings_db:
                defaults = self._settings_db.resolve_agent_config(request.agent_id)
                pending = self._settings_db.get_pending_queries_for_agent(request.agent_id)
                if pending:
                    defaults["pending_queries"] = pending
                # Inject surveillance targets from active incidents
                try:
                    surv = self._neo4j.get_surveillance_targets(request.agent_id)
                    if isinstance(surv, dict) and surv.get("ips"):
                        defaults["active_surveillance"] = surv
                except Exception:
                    logger.debug("Surveillance target lookup failed for %s", request.agent_id, exc_info=True)

                if defaults:
                    config_json = json.dumps(defaults)
                    signing_key = hmac.new(
                        agent_key.encode(), request.agent_id.encode(), hashlib.sha256
                    ).digest()
                    config_signature = hmac.new(
                        signing_key, config_json.encode(), hashlib.sha256
                    ).hexdigest()

            return fleet_pb2.HeartbeatResponse(
                acknowledged=True,
                message="ok",
                config_json=config_json,
                config_signature=config_signature,
            )
        except Exception:
            logger.debug("Heartbeat update failed for %s", request.agent_id, exc_info=True)
            return fleet_pb2.HeartbeatResponse(acknowledged=False, message="failed")
