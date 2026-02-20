"""Normalize raw events into OCSF ProcessActivity (class 1007)."""

from __future__ import annotations

import contextlib
import os
import socket
from datetime import datetime

import psutil

from agent.collectors.base import RawEvent
from agent.schema.ocsf_types import (
    ActorInfo,
    DeviceInfo,
    OcsfMetadata,
    ProcessActivity,
    ProcessInfo,
    UserInfo,
)


def normalize_process(raw: RawEvent) -> ProcessActivity | None:
    """Convert a RawEvent into an OCSF ProcessActivity.

    Returns None if the process cannot be identified (no name resolvable).
    """
    fields = raw.fields
    hostname = raw.hostname or socket.gethostname()

    pid = int(fields.get("pid", "0"))
    name = (
        fields.get("name", "")
        or fields.get("program", "")
        or _basename(fields.get("process", ""))
        or _basename(fields.get("exe", ""))
        or _basename(fields.get("image", ""))
    )
    username = fields.get("username", "") or fields.get("user", "") or ""
    cmdline = fields.get("cmdline", "") or fields.get("commandline", "") or ""
    exe = fields.get("exe", "") or fields.get("image", "") or fields.get("process", "") or ""
    ppid = int(fields.get("ppid", "0") or "0")

    # Resolve name via psutil if still empty and we have a PID
    if not name and pid > 0:
        name, username, exe = _resolve_pid(pid, username, exe)

    # Drop events where we still can't identify the process
    if not name:
        return None

    create_time = None
    if fields.get("create_time"):
        with contextlib.suppress(ValueError):
            create_time = datetime.fromisoformat(fields["create_time"])

    actor = None
    if username:
        actor = ActorInfo(user=UserInfo(name=username))

    return ProcessActivity(
        activity_id=1,  # Launch
        severity_id=1,  # Informational
        time=raw.timestamp,
        actor=actor,
        process=ProcessInfo(
            pid=pid,
            name=name,
            cmd_line=cmdline,
            exe_path=exe,
            parent_pid=ppid if ppid else None,
            created_time=create_time,
        ),
        device=DeviceInfo(hostname=hostname),
        metadata=OcsfMetadata(
            original_time=raw.timestamp,
            log_source=raw.source,
        ),
    )


def _basename(path: str) -> str:
    """Extract filename from a path, returning empty string if empty."""
    if not path:
        return ""
    return os.path.basename(path)


def _resolve_pid(pid: int, fallback_user: str, fallback_exe: str) -> tuple[str, str, str]:
    """Try to resolve a PID to a process name, username, and exe path via psutil."""
    try:
        proc = psutil.Process(pid)
        name = proc.name() or ""
        user = fallback_user or (proc.username() or "")
        exe = fallback_exe or (proc.exe() or "")
        return name, user, exe
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "", fallback_user, fallback_exe
