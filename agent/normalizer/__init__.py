"""Normalization pipeline: RawEvent -> OCSF events."""

from __future__ import annotations

import logging

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import OcsfEvent

from .authentication import normalize_authentication
from .dns_activity import normalize_dns
from .file_activity import normalize_file
from .network_activity import normalize_network
from .process_activity import normalize_process
from .registry_activity import normalize_registry

logger = logging.getLogger(__name__)

__all__ = ["normalize"]

# Map source names to normalizer functions
_NORMALIZERS: dict[str, callable] = {
    "psutil_process": normalize_process,
    "psutil_network": normalize_network,
    "auth": normalize_authentication,
    "auditd": normalize_process,
    "unified_log": normalize_process,
    "syslog": normalize_process,
    "macos_log": normalize_process,
}

# Windows sources
for _ch in ("evtlog_Security", "evtlog_System", "evtlog_Application"):
    _NORMALIZERS[_ch] = normalize_process
_NORMALIZERS["evtlog_Microsoft-Windows-Sysmon/Operational"] = normalize_process

# ETW sources
# Auditd netlink sources
_NORMALIZERS["auditd_execve"] = normalize_process
_NORMALIZERS["auditd_syscall"] = normalize_process

# eBPF sources
_NORMALIZERS["ebpf_execve"] = normalize_process
_NORMALIZERS["ebpf_network"] = normalize_network

# ETW sources
_NORMALIZERS["etw_process"] = normalize_process
_NORMALIZERS["etw_network"] = normalize_network
_NORMALIZERS["etw_dns"] = normalize_dns
_NORMALIZERS["etw_file"] = normalize_file
_NORMALIZERS["etw_registry"] = normalize_registry

# DNS sources
_NORMALIZERS["dns_resolve"] = normalize_dns
_NORMALIZERS["unified_log_dns"] = normalize_dns

# File activity sources
_NORMALIZERS["file_create"] = normalize_file
_NORMALIZERS["file_modify"] = normalize_file
_NORMALIZERS["file_read"] = normalize_file
_NORMALIZERS["file_delete"] = normalize_file
_NORMALIZERS["file_rename"] = normalize_file

# Registry activity sources
_NORMALIZERS["registry_create"] = normalize_registry
_NORMALIZERS["registry_modify"] = normalize_registry
_NORMALIZERS["registry_delete"] = normalize_registry


def normalize(raw: RawEvent) -> OcsfEvent | None:
    """Normalize a RawEvent into an OCSF event. Returns None if unmappable."""
    normalizer = _NORMALIZERS.get(raw.source)
    if normalizer is None:
        logger.debug("No normalizer for source: %s", raw.source)
        return None
    try:
        return normalizer(raw)
    except Exception:
        logger.debug("Failed to normalize event from %s", raw.source, exc_info=True)
        return None
