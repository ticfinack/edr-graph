"""Normalize raw events into OCSF NetworkActivity (class 4001)."""

from __future__ import annotations

import socket

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    DeviceInfo,
    NetworkActivity,
    NetworkEndpoint,
    OcsfMetadata,
    ProcessInfo,
)


def normalize_network(raw: RawEvent) -> NetworkActivity:
    """Convert a RawEvent into an OCSF NetworkActivity."""
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()

    pid = int(fields.get("pid", "0"))
    process_name = fields.get("process_name", "")

    process = None
    if pid or process_name:
        process = ProcessInfo(pid=pid, name=process_name)

    src_endpoint = None
    if fields.get("src_ip"):
        src_endpoint = NetworkEndpoint(
            ip=fields["src_ip"],
            port=int(fields.get("src_port", "0")),
        )

    dst_endpoint = None
    if fields.get("dst_ip"):
        dst_endpoint = NetworkEndpoint(
            ip=fields["dst_ip"],
            port=int(fields.get("dst_port", "0")),
        )

    return NetworkActivity(
        activity_id=1,  # Open
        severity_id=1,  # Informational
        time=raw.timestamp,
        src_endpoint=src_endpoint,
        dst_endpoint=dst_endpoint,
        process=process,
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )
