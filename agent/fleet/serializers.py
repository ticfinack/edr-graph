"""Serialize Pydantic models to protobuf messages for fleet forwarding."""

from __future__ import annotations

import json

from agent.fleet.proto import fleet_pb2
from agent.schema.graph_types import SecurityFinding


def finding_to_proto(finding: SecurityFinding) -> fleet_pb2.SecurityFinding:
    """Convert a SecurityFinding Pydantic model to its protobuf equivalent."""
    chain_steps = []
    for step in finding.chain:
        chain_steps.append(
            fleet_pb2.ChainStep(
                entity_type=step.entity_type,
                entity_id=step.entity_id,
                entity_name=step.entity_name,
                pid=step.pid or 0,
                timestamp=int(step.timestamp.timestamp()) if step.timestamp else 0,
            )
        )

    return fleet_pb2.SecurityFinding(
        id=finding.id,
        timestamp=int(finding.timestamp.timestamp()),
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        affected_entities=finding.affected_entities,
        evidence_event_ids=finding.evidence_event_ids,
        recommendation=finding.recommendation,
        chain=chain_steps,
        affected_pids=finding.affected_pids,
        iocs_json=json.dumps(finding.iocs),
    )


def proto_to_finding_dict(proto: fleet_pb2.SecurityFinding) -> dict:
    """Convert a protobuf SecurityFinding to a dict suitable for Neo4j ingestion."""
    return {
        "id": proto.id,
        "timestamp": proto.timestamp,
        "severity": proto.severity,
        "title": proto.title,
        "description": proto.description,
        "affected_entities": list(proto.affected_entities),
        "evidence_event_ids": list(proto.evidence_event_ids),
        "recommendation": proto.recommendation,
        "chain": [
            {
                "entity_type": s.entity_type,
                "entity_id": s.entity_id,
                "entity_name": s.entity_name,
                "pid": s.pid,
                "timestamp": s.timestamp,
            }
            for s in proto.chain
        ],
        "affected_pids": list(proto.affected_pids),
        "iocs": json.loads(proto.iocs_json) if proto.iocs_json else {},
    }
