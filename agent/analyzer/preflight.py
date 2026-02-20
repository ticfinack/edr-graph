"""Pre-flight novelty filter: only send novel edges to the LLM."""

from __future__ import annotations

import logging
import re
import sys

import kuzu

from agent.schema.ocsf_types import (
    Authentication,
    NetworkActivity,
    OcsfEvent,
    ProcessActivity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Baseline of known-benign system processes per platform.
# Events from these processes are DROPPED unless they have a command line
# that references a LOLBin/GTFOBin/LOOBin (checked separately by the LLM).
# This prevents the LLM from wasting tokens on routine daemon log noise.
# ---------------------------------------------------------------------------

_MACOS_SYSTEM_BASELINE: frozenset[str] = frozenset(
    {
        # Core system
        "kernel",
        "launchd",
        "kernel_task",
        # Display / UI
        "WindowServer",
        "Dock",
        "SystemUIServer",
        "ControlCenter",
        "NotificationCenter",
        "Spotlight",
        "loginwindow",
        "WallpaperAerialsExtension",
        "WallpaperVideoExtension",
        # Process management
        "runningboardd",
        "dasd",
        "distnoted",
        "cfprefsd",
        "lsd",
        "trustd",
        "syspolicyd",
        "endpointsecurityd",
        # Storage / Filesystem
        "corespotlightd",
        "spotlightknowledged",
        "mds",
        "mds_stores",
        "mdworker",
        "mdworker_shared",
        "fseventsd",
        "filecoordinationd",
        "fileproviderd",
        "revisiond",
        # Networking
        "mDNSResponder",
        "configd",
        "symptomsd",
        "networkd",
        "nsurlsessiond",
        "apsd",
        "identityservicesd",
        "wirelessproxd",
        "bluetoothd",
        "bluetoothaudiod",
        "WiFiAgent",
        "airportd",
        # Security / Auth
        "securityd",
        "opendirectoryd",
        "AuthenticationServicesAgent",
        # Power / Hardware
        "powerd",
        "thermalmonitord",
        "coreduetd",
        "ioreportMacScheduler",
        "syslogd",
        "systemstats",
        "diagnosticd",
        # iCloud / Apple services
        "cloudd",
        "bird",
        "mediaremoted",
        "callservicesd",
        "akd",
        "amsaccountsd",
        # User apps (routine)
        "Safari",
        "Finder",
        "Mail",
        "Messages",
        "Calendar",
        "Notes",
        "Reminders",
        "Maps",
        "Photos",
        "Music",
        "TV",
        "Podcasts",
        "News",
        "Stocks",
        "Home",
        "Books",
        "Preview",
        "TextEdit",
        "Terminal",
        "Activity Monitor",
        "System Preferences",
        "System Settings",
        "App Store",
        "FaceTime",
        # WebKit / browser helpers
        "com.apple.WebKit.Networking",
        "com.apple.WebKit.WebContent",
        "com.apple.WebKit.GPU",
        "com.apple.Safari.WebHosting",
        "SafariBookmarksSyncAgent",
        # System agents
        "UserEventAgent",
        "contextstored",
        "duetexpertd",
        "knowledge-agent",
        "progressd",
        "remindd",
        "CalendarAgent",
        "AddressBookSourceSync",
        "containermanagerd",
        "containermanager",
        "siriknowledged",
        "assistantd",
        "parsecd",
        "suggestd",
        "searchpartyd",
        "rapportd",
        "sharingd",
        "coreservicesd",
        "iconservicesagent",
        # Other background daemons
        "logd",
        "watchdogd",
        "mediaanalysisd",
        "photoanalysisd",
        "gamepolicyd",
        "gamecontrollerd",
        "donotdisturbd",
        "UIKitSystem",
        "ViewBridgeAuxiliary",
        "talagent",
        "AMPDeviceDiscoveryAgent",
        "AMPLibraryAgent",
        "CategoriesService",
        "analyticsagent",
        # Creative Cloud (common on developer machines)
        "Creative Cloud Helper",
        "Creative Cloud UI Helper (Renderer)",
        "Creative Cloud Libraries Synchronizer",
        "Core Sync",
        "CCXProcess",
        "CCLibrary",
        "AdobeIPCBroker",
        "com.adobe.acc.HEXProductSearchService",
        # Claude / dev tools (self — don't flag ourselves)
        "Claude",
        "Claude Helper",
        "Web App",
        # EDR agent itself
        "edr-graph",
    }
)

_LINUX_SYSTEM_BASELINE: frozenset[str] = frozenset(
    {
        "systemd",
        "systemd-journald",
        "systemd-logind",
        "systemd-udevd",
        "systemd-resolved",
        "systemd-timesyncd",
        "systemd-networkd",
        "init",
        "kthreadd",
        "dbus-daemon",
        "polkitd",
        "rsyslogd",
        "cron",
        "atd",
        "NetworkManager",
        "wpa_supplicant",
        "avahi-daemon",
        "cupsd",
        "accounts-daemon",
        "snapd",
        "packagekitd",
        "udisksd",
        "thermald",
        "irqbalance",
        "acpid",
        "ModemManager",
        "gdm",
        "gdm-session-worker",
        "gnome-shell",
        "gnome-session",
        "Xorg",
        "Xwayland",
        "pulseaudio",
        "pipewire",
    }
)

_WINDOWS_SYSTEM_BASELINE: frozenset[str] = frozenset(
    {
        "System",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "dwm.exe",
        "explorer.exe",
        "taskhostw.exe",
        "RuntimeBroker.exe",
        "ShellExperienceHost.exe",
        "SearchUI.exe",
        "SearchApp.exe",
        "StartMenuExperienceHost.exe",
        "ctfmon.exe",
        "conhost.exe",
        "sihost.exe",
        "fontdrvhost.exe",
        "WmiPrvSE.exe",
        "dllhost.exe",
        "msiexec.exe",
        "TiWorker.exe",
        "spoolsv.exe",
        "lsaiso.exe",
        "SecurityHealthService.exe",
        "MsMpEng.exe",
        "NisSrv.exe",
    }
)


# Patterns for the EDR agent's own processes and its launcher (Claude Code).
# Claude Code's binary lives under ~/.local/share/claude/versions/<semver>
# so psutil reports the version string (e.g. "2.1.45") as the process name.
_AGENT_NAME_RE = re.compile(
    r"^("
    r"edr-graph"
    r"|python\d*(\.\d+)*"  # python, python3, python3.13, …
    r"|Python"
    r"|\d+\.\d+\.\d+"  # semver like 2.1.45 (Claude Code)
    r")$"
)


def _is_agent_process(proc_name: str) -> bool:
    """Return True if *proc_name* belongs to the agent or its launcher."""
    return bool(_AGENT_NAME_RE.match(proc_name))


def _get_system_baseline() -> frozenset[str]:
    """Return the baseline set for the current platform."""
    if sys.platform == "darwin":
        return _MACOS_SYSTEM_BASELINE
    elif sys.platform == "win32":
        return _WINDOWS_SYSTEM_BASELINE
    else:
        return _LINUX_SYSTEM_BASELINE


# Materialise once at import time
SYSTEM_BASELINE: frozenset[str] = _get_system_baseline()


def is_novel(conn: kuzu.Connection, event: OcsfEvent, threshold: int = 5) -> bool:
    """Check if an event represents novel behavior worth sending to the LLM.

    Returns True if the edge has been seen <= threshold times (novel).
    Returns False if it's routine behavior (seen > threshold times).
    Returns False for events that lack identifiable entities.
    Returns False for known-benign system processes (baseline).
    """
    try:
        if isinstance(event, ProcessActivity):
            return _check_process_novelty(conn, event, threshold)
        elif isinstance(event, NetworkActivity):
            return _check_network_novelty(conn, event, threshold)
        elif isinstance(event, Authentication):
            return _check_auth_novelty(conn, event, threshold)
    except Exception:
        logger.debug("Pre-flight check failed, treating as novel", exc_info=True)

    return True  # Unknown event types or errors -> always send to LLM


def _check_process_novelty(conn: kuzu.Connection, event: ProcessActivity, threshold: int) -> bool:
    """Has this process name been spawned before (by any user)?"""
    proc_name = event.process.name
    if not proc_name:
        return False  # Unidentifiable process, drop it

    # Drop the agent's own processes (version-string names, python variants)
    if _is_agent_process(proc_name):
        return False

    # Drop known-benign system processes (unless they have a suspicious cmd_line)
    if proc_name in SYSTEM_BASELINE:
        cmd = event.process.cmd_line or ""
        # Let through if the process is executing with unusual arguments
        # (e.g. curl piped to sh, osascript with -e flags, etc.)
        if not cmd or proc_name in cmd.split()[0] if cmd.split() else True:
            return False

    # Check if ANY user has spawned this process name more than threshold times
    result = conn.execute(
        "MATCH (u:User)-[s:SPAWNED]->(p:Process) WHERE p.name = $proc_name RETURN count(s) AS cnt",
        {"proc_name": proc_name},
    )
    if result.has_next():
        count = result.get_next()[0]
        return count <= threshold

    # No SPAWNED edges at all — check if we've seen this process name in the
    # Process node table at all (covers unified log events without actor)
    result = conn.execute(
        "MATCH (p:Process) WHERE p.name = $proc_name RETURN count(p) AS cnt",
        {"proc_name": proc_name},
    )
    if result.has_next():
        count = result.get_next()[0]
        return count <= threshold

    return True  # Never seen before -> novel


def _check_network_novelty(conn: kuzu.Connection, event: NetworkActivity, threshold: int) -> bool:
    """Has this process connected to this IP before?"""
    if not event.process or not event.dst_endpoint:
        return False  # No identifiable process or destination, drop it

    proc_name = event.process.name
    dst_ip = event.dst_endpoint.ip
    if not proc_name or not dst_ip:
        return False  # Unidentifiable, drop it

    # Drop the agent's own network connections
    if _is_agent_process(proc_name):
        return False

    # Drop known-benign system processes making network connections
    if proc_name in SYSTEM_BASELINE:
        return False

    result = conn.execute(
        "MATCH (p:Process {name: $proc})-[c:CONNECTED_TO]->(ip:IP {id: $ip}) RETURN count(c) AS cnt",
        {"proc": proc_name, "ip": dst_ip},
    )
    if result.has_next():
        count = result.get_next()[0]
        return count <= threshold
    return True


def _check_auth_novelty(conn: kuzu.Connection, event: Authentication, threshold: int) -> bool:
    """Has this user been seen before?"""
    username = event.user.name
    if not username:
        return False  # No user, drop it

    result = conn.execute(
        "MATCH (u:User {id: $user}) RETURN count(u) AS cnt",
        {"user": username},
    )
    if result.has_next():
        count = result.get_next()[0]
        return count <= threshold
    return True
