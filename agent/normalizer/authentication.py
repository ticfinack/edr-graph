"""Normalize raw events into OCSF Authentication (class 3002)."""

from __future__ import annotations

import re
import socket

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    Authentication,
    DeviceInfo,
    NetworkEndpoint,
    OcsfMetadata,
    UserInfo,
)


def normalize_authentication(raw: RawEvent) -> Authentication:
    """Convert a RawEvent into an OCSF Authentication event."""
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()
    message = raw.message.lower()

    # Determine activity and status
    activity_id = 1  # Logon
    status_id = 1  # Success
    severity_id = 1

    if "logout" in message or "logoff" in message or "session closed" in message:
        activity_id = 2  # Logoff
    if "failed" in message or "failure" in message or "invalid" in message:
        status_id = 2  # Failure
        severity_id = 3  # Medium

    # Extract user
    username = fields.get("user", "") or fields.get("username", "")
    if not username:
        user_match = re.search(r"(?:user|for)\s+(\S+)", raw.message)
        if user_match:
            username = user_match.group(1)
    username = username or "unknown"

    # Extract source IP
    src_endpoint = None
    src_ip = fields.get("src_ip", "")
    if not src_ip:
        ip_match = re.search(r"from\s+([\d.]+)", raw.message)
        if ip_match:
            src_ip = ip_match.group(1)
    if src_ip:
        src_endpoint = NetworkEndpoint(ip=src_ip)

    return Authentication(
        activity_id=activity_id,
        status_id=status_id,
        severity_id=severity_id,
        time=raw.timestamp,
        user=UserInfo(name=username),
        src_endpoint=src_endpoint,
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )
