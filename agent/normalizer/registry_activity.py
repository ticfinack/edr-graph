"""Normalize raw events into OCSF RegistryActivity."""

from __future__ import annotations

import logging
import socket
import sys

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    DeviceInfo,
    OcsfMetadata,
    ProcessInfo,
    RegistryActivity,
)

logger = logging.getLogger(__name__)

_ACTIVITY_MAP = {
    "registry_create": 1,
    "registry_modify": 3,
    "registry_delete": 4,
}


def normalize_registry(raw: RawEvent) -> RegistryActivity:
    """Convert a RawEvent into an OCSF RegistryActivity."""
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()

    pid = int(fields.get("pid", "0"))
    process_name = fields.get("name", "") or fields.get("process_name", "")

    process = None
    if pid or process_name:
        process = ProcessInfo(pid=pid, name=process_name)

    reg_path = fields.get("reg_path", "") or fields.get("path", "")
    value_name = fields.get("value_name") or None
    value_data = fields.get("value_data") or None

    event_type = fields.get("event_type", raw.source)
    activity_id = _ACTIVITY_MAP.get(event_type, 3)

    # Capture previous data on modify events (Windows only)
    previous_data = None
    if activity_id == 3 and sys.platform == "win32":
        previous_data = _read_registry_value(reg_path, value_name)

    return RegistryActivity(
        activity_id=activity_id,
        severity_id=1,
        time=raw.timestamp,
        process=process,
        reg_path=reg_path,
        reg_value_name=value_name,
        reg_value_data=value_data,
        reg_previous_data=previous_data,
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )


def _read_registry_value(path: str, value_name: str | None) -> str | None:
    """Read the current registry value before a modification (Windows only)."""
    if sys.platform != "win32":
        return None
    try:
        import winreg  # noqa: F401

        # Parse hive from path
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        }
        parts = path.split("\\", 1)
        if len(parts) < 2:
            return None
        hive = hive_map.get(parts[0])
        if hive is None:
            return None
        subkey = parts[1]
        with winreg.OpenKey(hive, subkey) as key:
            data, _ = winreg.QueryValueEx(key, value_name or "")
            return str(data)
    except Exception:
        logger.debug("Cannot read registry value %s\\%s", path, value_name, exc_info=True)
        return None
