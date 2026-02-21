"""Normalize raw events into OCSF FileActivity (class 1001)."""

from __future__ import annotations

import hashlib
import logging
import os
import socket

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    DeviceInfo,
    FileActivity,
    OcsfMetadata,
    ProcessInfo,
)

logger = logging.getLogger(__name__)

# Map source event_type field values to OCSF activity IDs
_ACTIVITY_MAP = {
    "file_create": 1,
    "file_read": 2,
    "file_modify": 3,
    "file_delete": 4,
    "file_rename": 3,  # Treat rename as modify for graph edges
}

_MAX_HASH_SIZE = 100 * 1024 * 1024  # 100MB


def normalize_file(raw: RawEvent) -> FileActivity:
    """Convert a RawEvent into an OCSF FileActivity."""
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()

    pid = int(fields.get("pid", "0"))
    process_name = fields.get("name", "") or fields.get("process_name", "")

    # FSEvents reports PID 0 — try to attribute the file to a real process
    file_path_raw = fields.get("file_path", "") or fields.get("path", "")
    if pid == 0 and file_path_raw:
        try:
            from agent.enrichment.file_attribution import get_file_attribution_cache

            owner = get_file_attribution_cache().lookup(file_path_raw)
            if owner:
                pid = owner.pid
                process_name = owner.name
        except Exception:
            pass

    # If attribution failed, don't carry forward placeholder names
    if pid == 0:
        process_name = ""

    process = None
    if pid or process_name:
        process = ProcessInfo(pid=pid, name=process_name)

    file_path = fields.get("file_path", "") or fields.get("path", "")
    event_type = fields.get("event_type", raw.source)
    activity_id = _ACTIVITY_MAP.get(event_type, 3)  # default to modify

    # Attempt SHA256 hash if file exists
    file_hash = None
    file_size = None
    if file_path:
        file_hash, file_size = _compute_file_info(file_path)

    return FileActivity(
        activity_id=activity_id,
        severity_id=1,
        time=raw.timestamp,
        process=process,
        file_path=file_path,
        file_hash_sha256=file_hash,
        file_size=file_size,
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )


def _compute_file_info(path: str) -> tuple[str | None, int | None]:
    """Compute SHA256 hash and size of a file. Non-blocking: returns (None, None) on failure."""
    try:
        stat = os.stat(path)
        file_size = stat.st_size
        if file_size > _MAX_HASH_SIZE:
            logger.warning("Skipping hash for large file (%d bytes): %s", file_size, path)
            return None, file_size
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest(), file_size
    except (OSError, PermissionError) as e:
        logger.warning("Cannot hash file %s: %s", path, e)
        return None, None
