"""Normalize raw events into OCSF DnsActivity (class 4003)."""

from __future__ import annotations

import socket

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    DeviceInfo,
    DnsActivity,
    OcsfMetadata,
    ProcessInfo,
)


def normalize_dns(raw: RawEvent) -> DnsActivity:
    """Convert a RawEvent into an OCSF DnsActivity."""
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()

    pid = int(fields.get("pid", "0"))
    process_name = fields.get("name", "") or fields.get("process_name", "")

    process = None
    if pid or process_name:
        process = ProcessInfo(pid=pid, name=process_name)

    query_domain = fields.get("query_domain", "") or fields.get("domain", "")

    resolved_ips_raw = fields.get("resolved_ips", "")
    if isinstance(resolved_ips_raw, list):
        resolved_ips = resolved_ips_raw
    elif resolved_ips_raw:
        resolved_ips = [ip.strip() for ip in resolved_ips_raw.split(",") if ip.strip()]
    else:
        resolved_ips = []

    return DnsActivity(
        activity_id=1,  # Query
        severity_id=1,
        time=raw.timestamp,
        process=process,
        query_domain=query_domain,
        resolved_ips=resolved_ips,
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )
