"""Rule-based persistence detection for registry and filesystem paths.

Platform-aware detector that monitors paths commonly abused for persistence.
Runs on every file_create, file_modify, registry_create, and registry_modify event.
Must complete in < 0.1ms per event (string prefix matching).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from agent.schema.ocsf_types import FileActivity, OcsfEvent, RegistryActivity

# ============================================================================
# Windows Registry Persistence Paths
# ============================================================================

WINDOWS_PERSISTENCE_KEYS: dict[str, tuple[str, str]] = {
    # path_prefix -> (persistence_type, mitre_technique_id)
    # Run keys
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": (
        "registry_run_key", "T1547.001"
    ),
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce": (
        "registry_run_key", "T1547.001"
    ),
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run": (
        "registry_run_key", "T1547.001"
    ),
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce": (
        "registry_run_key", "T1547.001"
    ),
    # Services
    r"HKLM\SYSTEM\CurrentControlSet\Services": (
        "windows_service", "T1543.003"
    ),
    # Winlogon
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell": (
        "winlogon", "T1547.001"
    ),
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit": (
        "winlogon", "T1547.001"
    ),
    # COM hijack vectors
    r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers": (
        "com_hijack", "T1546.015"
    ),
    r"HKLM\SOFTWARE\Classes\CLSID": (
        "com_hijack", "T1546.015"
    ),
    # WMI persistence
    r"HKLM\SOFTWARE\Microsoft\WBEM\ESS": (
        "wmi_event_subscription", "T1546.003"
    ),
    # Scheduled tasks
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache": (
        "scheduled_task", "T1053.005"
    ),
    # AppInit DLLs
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs": (
        "appinit_dlls", "T1546.010"
    ),
    # Image File Execution Options
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options": (
        "ifeo_debugger", "T1546.012"
    ),
}

# ============================================================================
# macOS Persistence Paths
# ============================================================================

MACOS_PERSISTENCE_PATHS: dict[str, tuple[str, str]] = {
    # path_prefix -> (persistence_type, mitre_technique_id)
    "~/Library/LaunchAgents/": ("launch_agent", "T1543.001"),
    "/Library/LaunchAgents/": ("launch_agent", "T1543.001"),
    "/Library/LaunchDaemons/": ("launch_daemon", "T1543.004"),
    "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/": (
        "launch_agent", "T1543.001"
    ),
    "/Library/StartupItems/": ("startup_items", "T1543.004"),
    "/etc/periodic/": ("periodic_script", "T1053.003"),
    "~/Library/Preferences/": ("login_items", "T1547.015"),
}

# ============================================================================
# Linux Persistence Paths
# ============================================================================

LINUX_PERSISTENCE_PATHS: dict[str, tuple[str, str]] = {
    # path_prefix -> (persistence_type, mitre_technique_id)
    "/etc/cron.d/": ("cron_job", "T1053.003"),
    "/etc/cron.daily/": ("cron_job", "T1053.003"),
    "/etc/cron.hourly/": ("cron_job", "T1053.003"),
    "/etc/cron.weekly/": ("cron_job", "T1053.003"),
    "/etc/cron.monthly/": ("cron_job", "T1053.003"),
    "/var/spool/cron/": ("cron_job", "T1053.003"),
    "/etc/systemd/system/": ("systemd_unit", "T1543.002"),
    "/usr/lib/systemd/system/": ("systemd_unit", "T1543.002"),
    "~/.config/systemd/user/": ("systemd_unit", "T1543.002"),
    "/etc/init.d/": ("init_script", "T1543.002"),
    "/etc/rc.local": ("init_script", "T1543.002"),
    "~/.bashrc": ("shell_profile", "T1546.004"),
    "~/.bash_profile": ("shell_profile", "T1546.004"),
    "~/.profile": ("shell_profile", "T1546.004"),
    "/etc/ld.so.preload": ("ld_preload", "T1574.006"),
}

# MITRE ATT&CK technique name lookup
_MITRE_NAMES: dict[str, str] = {
    "T1547.001": "Boot/Logon Autostart: Registry Run Keys",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task",
    "T1546.003": "Event Triggered Execution: WMI",
    "T1546.010": "Event Triggered Execution: AppInit DLLs",
    "T1546.012": "Event Triggered Execution: IFEO",
    "T1546.015": "Event Triggered Execution: COM Object Hijacking",
    "T1543.001": "Create or Modify System Process: Launch Agent",
    "T1543.004": "Create or Modify System Process: Launch Daemon",
    "T1053.003": "Scheduled Task: Cron",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1546.004": "Event Triggered Execution: Unix Shell Config",
    "T1574.006": "Hijack Execution Flow: Dynamic Linker Hijacking",
    "T1547.015": "Boot/Logon Autostart: Login Items",
}


@dataclass
class PersistenceResult:
    path: str  # The registry key or file path that was written
    persistence_type: str  # "registry_run_key", "launch_agent", "cron_job", etc.
    platform: str  # "windows", "macos", "linux"
    severity: str  # Always "HIGH" for known persistence paths
    mitre_technique: str  # ATT&CK ID: "T1547.001", "T1543.001", etc.
    description: str  # Human-readable


def check_persistence(event: OcsfEvent) -> PersistenceResult | None:
    """Check if an event represents a persistence mechanism installation.

    Returns None if the event is not persistence-related.
    """
    if isinstance(event, RegistryActivity):
        if event.activity_id in (1, 3):  # Create or Modify
            return _check_registry_persistence(event)
    elif isinstance(event, FileActivity):
        if event.activity_id in (1, 3):  # Create or Modify
            return _check_file_persistence(event)
    return None


def _check_registry_persistence(event: RegistryActivity) -> PersistenceResult | None:
    """Check registry writes against known persistence paths."""
    reg_path = event.reg_path
    if not reg_path:
        return None

    # Normalize path for comparison
    reg_upper = reg_path.upper()
    for prefix, (ptype, technique) in WINDOWS_PERSISTENCE_KEYS.items():
        if reg_upper.startswith(prefix.upper()):
            process_name = event.process.name if event.process else "unknown"
            return PersistenceResult(
                path=reg_path,
                persistence_type=ptype,
                platform="windows",
                severity="HIGH",
                mitre_technique=technique,
                description=(
                    f"Process {process_name} wrote to {ptype} "
                    f"({_MITRE_NAMES.get(technique, technique)}): {reg_path}"
                ),
            )
    return None


def _check_file_persistence(event: FileActivity) -> PersistenceResult | None:
    """Check file writes against known persistence paths."""
    file_path = event.file_path
    if not file_path:
        return None

    # Expand ~ for comparison
    home = os.path.expanduser("~")

    # Check platform-specific paths
    if sys.platform == "darwin":
        return _match_file_paths(event, file_path, home, MACOS_PERSISTENCE_PATHS, "macos")
    elif sys.platform == "linux":
        return _match_file_paths(event, file_path, home, LINUX_PERSISTENCE_PATHS, "linux")
    else:
        # On other platforms, check both (for cross-platform testing)
        result = _match_file_paths(event, file_path, home, MACOS_PERSISTENCE_PATHS, "macos")
        if result:
            return result
        return _match_file_paths(event, file_path, home, LINUX_PERSISTENCE_PATHS, "linux")


def check_persistence_for_path(
    file_path: str,
    process_name: str = "unknown",
    platform: str | None = None,
) -> PersistenceResult | None:
    """Check a file path against persistence paths.

    Platform-independent version for direct path checking.
    """
    if not file_path:
        return None

    home = os.path.expanduser("~")
    target_platform = platform or _detect_platform()

    if target_platform == "macos":
        paths = MACOS_PERSISTENCE_PATHS
    elif target_platform == "linux":
        paths = LINUX_PERSISTENCE_PATHS
    else:
        # Check all
        paths = {**MACOS_PERSISTENCE_PATHS, **LINUX_PERSISTENCE_PATHS}

    for prefix, (ptype, technique) in paths.items():
        expanded = prefix.replace("~", home)
        if file_path.startswith(expanded):
            return PersistenceResult(
                path=file_path,
                persistence_type=ptype,
                platform=target_platform,
                severity="HIGH",
                mitre_technique=technique,
                description=(
                    f"Process {process_name} wrote to {ptype} "
                    f"({_MITRE_NAMES.get(technique, technique)}): {file_path}"
                ),
            )
    return None


def check_persistence_for_registry(
    reg_path: str,
    process_name: str = "unknown",
) -> PersistenceResult | None:
    """Check a registry path against persistence paths."""
    if not reg_path:
        return None

    reg_upper = reg_path.upper()
    for prefix, (ptype, technique) in WINDOWS_PERSISTENCE_KEYS.items():
        if reg_upper.startswith(prefix.upper()):
            return PersistenceResult(
                path=reg_path,
                persistence_type=ptype,
                platform="windows",
                severity="HIGH",
                mitre_technique=technique,
                description=(
                    f"Process {process_name} wrote to {ptype} "
                    f"({_MITRE_NAMES.get(technique, technique)}): {reg_path}"
                ),
            )
    return None


def _match_file_paths(
    event: FileActivity,
    file_path: str,
    home: str,
    paths: dict[str, tuple[str, str]],
    platform: str,
) -> PersistenceResult | None:
    """Match a file path against a set of persistence path prefixes."""
    process_name = event.process.name if event.process else "unknown"

    for prefix, (ptype, technique) in paths.items():
        expanded = prefix.replace("~", home)
        if file_path.startswith(expanded):
            return PersistenceResult(
                path=file_path,
                persistence_type=ptype,
                platform=platform,
                severity="HIGH",
                mitre_technique=technique,
                description=(
                    f"Process {process_name} wrote to {ptype} "
                    f"({_MITRE_NAMES.get(technique, technique)}): {file_path}"
                ),
            )
    return None


def _detect_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    elif sys.platform == "linux":
        return "linux"
    return "windows"
