"""Round-trip serialization for OCSF events and ExtractedEntities.

Handles JSON encode/decode with type discrimination via ``class_uid``
for OCSF events, and structured serialization for graph entities.
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime
from typing import Any

from agent.schema.ocsf_types import (
    Authentication,
    DnsActivity,
    FileActivity,
    NetworkActivity,
    OcsfEvent,
    ProcessActivity,
    RegistryActivity,
)

logger = logging.getLogger(__name__)

_CLASS_UID_MAP: dict[int, type] = {
    1007: ProcessActivity,
    4001: NetworkActivity,
    3002: Authentication,
    4003: DnsActivity,
    1001: FileActivity,
    201001: RegistryActivity,
}


def serialize_ocsf(event: OcsfEvent) -> str:
    """Serialize an OCSF event to JSON, preserving the class_uid discriminator."""
    return event.model_dump_json()


def deserialize_ocsf(json_str: str) -> OcsfEvent:
    """Deserialize an OCSF event from JSON, dispatching on class_uid."""
    data = json.loads(json_str)
    class_uid = data.get("class_uid")
    model_cls = _CLASS_UID_MAP.get(class_uid)
    if model_cls is None:
        raise ValueError(f"Unknown class_uid: {class_uid}")
    return model_cls.model_validate(data)


def _datetime_handler(obj: Any) -> str:
    """JSON serializer for datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def serialize_entities(entities) -> str:
    """Serialize ExtractedEntities to JSON.

    Pydantic nodes use model_dump(); edge dicts are serialized directly.
    """
    data = {
        "users": [u.model_dump() for u in entities.users],
        "processes": [p.model_dump() for p in entities.processes],
        "ips": [ip.model_dump() for ip in entities.ips],
        "domains": [d.model_dump() for d in entities.domains],
        "files": [f.model_dump() for f in entities.files],
        "registry_keys": [r.model_dump() for r in entities.registry_keys],
        "spawned_edges": entities.spawned_edges,
        "connected_edges": entities.connected_edges,
        "resolved_edges": entities.resolved_edges,
        "resolves_to_edges": entities.resolves_to_edges,
        "file_edges": entities.file_edges,
        "registry_edges": entities.registry_edges,
        "risk_indicators": entities.risk_indicators,
    }
    return json.dumps(data, default=_datetime_handler)


def _rehydrate_edge_timestamps(edges: list[dict]) -> list[dict]:
    """Convert ISO-format timestamp strings back to datetime objects in edge dicts."""
    for edge in edges:
        ts = edge.get("timestamp")
        if isinstance(ts, str):
            with contextlib.suppress(ValueError, TypeError):
                edge["timestamp"] = datetime.fromisoformat(ts)
    return edges


def deserialize_entities(json_str: str):
    """Deserialize ExtractedEntities from JSON."""
    from agent.processor.entity_extractor import ExtractedEntities
    from agent.schema.graph_types import (
        DomainNode,
        FileNode,
        IpNode,
        ProcessNode,
        RegistryKeyNode,
        UserNode,
    )

    data = json.loads(json_str)
    entities = ExtractedEntities()
    entities.users = [UserNode.model_validate(u) for u in data.get("users", [])]
    entities.processes = [ProcessNode.model_validate(p) for p in data.get("processes", [])]
    entities.ips = [IpNode.model_validate(ip) for ip in data.get("ips", [])]
    entities.domains = [DomainNode.model_validate(d) for d in data.get("domains", [])]
    entities.files = [FileNode.model_validate(f) for f in data.get("files", [])]
    entities.registry_keys = [RegistryKeyNode.model_validate(r) for r in data.get("registry_keys", [])]
    entities.spawned_edges = _rehydrate_edge_timestamps(data.get("spawned_edges", []))
    entities.connected_edges = _rehydrate_edge_timestamps(data.get("connected_edges", []))
    entities.resolved_edges = _rehydrate_edge_timestamps(data.get("resolved_edges", []))
    entities.resolves_to_edges = _rehydrate_edge_timestamps(data.get("resolves_to_edges", []))
    entities.file_edges = _rehydrate_edge_timestamps(data.get("file_edges", []))
    entities.registry_edges = _rehydrate_edge_timestamps(data.get("registry_edges", []))
    entities.risk_indicators = data.get("risk_indicators", [])
    return entities
