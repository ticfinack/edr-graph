"""SANS "Hunt Evil" process hierarchy rules.

Encodes the expected parent-child process relationships from:
- SANS "Hunt Evil" poster (Windows)
- SANS Linux Incident Response process tree knowledge
- macOS expected process hierarchy

If a process violates these rules, it is highly suspicious.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Windows Process Hierarchy (SANS Hunt Evil Poster)
# Format: process_name -> { expected_parents, expected_user, notes }
# --------------------------------------------------------------------------

WINDOWS_HIERARCHY: dict[str, dict] = {
    "system": {
        "expected_parents": [],
        "expected_pid": 4,
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "notes": "Always PID 4. No parent. Kernel-level process.",
        "suspicious_if": "PID is not 4, or has a parent process",
    },
    "smss.exe": {
        "expected_parents": ["system"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\smss.exe",
        "notes": "Session Manager. First user-mode process. Only one instance after boot.",
        "suspicious_if": "Parent is not System (PID 4), running from wrong path, or multiple instances",
    },
    "csrss.exe": {
        "expected_parents": ["smss.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\csrss.exe",
        "notes": "Client/Server Runtime. One per session (Session 0 + Session 1).",
        "suspicious_if": "Parent is not smss.exe, wrong path, or unexpected number of instances",
    },
    "wininit.exe": {
        "expected_parents": ["smss.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\wininit.exe",
        "notes": "Windows Initialization. Starts services.exe, lsass.exe, lsm.exe. Session 0 only.",
        "suspicious_if": "Parent is not smss.exe, or more than one instance",
    },
    "winlogon.exe": {
        "expected_parents": ["smss.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\winlogon.exe",
        "notes": "Windows Logon. One per user session. Handles SAS (Ctrl+Alt+Del).",
        "suspicious_if": "Parent is not smss.exe, or running in Session 0",
    },
    "services.exe": {
        "expected_parents": ["wininit.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\services.exe",
        "notes": "Service Control Manager. MUST be child of wininit.exe. Only one instance.",
        "suspicious_if": "Parent is not wininit.exe, wrong path, or multiple instances",
    },
    "lsass.exe": {
        "expected_parents": ["wininit.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "expected_path": "%SystemRoot%\\System32\\lsass.exe",
        "notes": "Local Security Authority. Handles authentication. CRITICAL: only ONE instance.",
        "suspicious_if": "Parent is not wininit.exe, more than one instance (mimikatz!), or wrong path",
    },
    "svchost.exe": {
        "expected_parents": ["services.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM|LOCAL SERVICE|NETWORK SERVICE",
        "expected_path": "%SystemRoot%\\System32\\svchost.exe",
        "expected_cmdline_contains": "-k",
        "notes": "Service Host. MUST be child of services.exe. MUST have -k flag.",
        "suspicious_if": "Parent is NOT services.exe, missing -k flag, wrong path, or running as user account",
    },
    "explorer.exe": {
        "expected_parents": ["userinit.exe"],
        "expected_user": "<logged-on user>",
        "expected_path": "%SystemRoot%\\explorer.exe",
        "notes": "Windows Shell. One per logged-on user. Parent is userinit.exe (which exits).",
        "suspicious_if": "Running as SYSTEM, or spawned by unexpected parent like cmd.exe",
    },
    "taskhostw.exe": {
        "expected_parents": ["svchost.exe"],
        "expected_user": "varies",
        "expected_path": "%SystemRoot%\\System32\\taskhostw.exe",
        "notes": "Task Host. Runs scheduled tasks. Should be child of svchost.exe.",
        "suspicious_if": "Parent is not svchost.exe",
    },
    "lsaiso.exe": {
        "expected_parents": ["wininit.exe"],
        "expected_user": "NT AUTHORITY\\SYSTEM",
        "notes": "Credential Guard. Only present if Credential Guard is enabled.",
        "suspicious_if": "Present when Credential Guard is not enabled",
    },
    "runtimebroker.exe": {
        "expected_parents": ["svchost.exe"],
        "expected_user": "<logged-on user>",
        "expected_path": "%SystemRoot%\\System32\\RuntimeBroker.exe",
        "notes": "UWP app permission broker.",
        "suspicious_if": "Parent is not svchost.exe, or running as SYSTEM",
    },
}

# --------------------------------------------------------------------------
# Linux Process Hierarchy (SANS Linux IR + Standard Knowledge)
# --------------------------------------------------------------------------

LINUX_HIERARCHY: dict[str, dict] = {
    "systemd": {
        "expected_parents": [],
        "expected_pid": 1,
        "expected_user": "root",
        "notes": "PID 1. Init system. Parent of all user-space processes.",
        "suspicious_if": "PID is not 1, or has a parent",
    },
    "init": {
        "expected_parents": [],
        "expected_pid": 1,
        "expected_user": "root",
        "notes": "Legacy init. PID 1 on non-systemd systems.",
        "suspicious_if": "PID is not 1",
    },
    "kthreadd": {
        "expected_parents": [],
        "expected_pid": 2,
        "expected_user": "root",
        "notes": "Kernel thread daemon. PID 2. Parent of ALL kernel threads.",
        "suspicious_if": "PID is not 2, or user-space process claims kthreadd as parent",
    },
    "sshd": {
        "expected_parents": ["systemd", "init"],
        "expected_user": "root",
        "notes": "SSH daemon. Master process runs as root. Child per-connection runs as user.",
        "suspicious_if": "Parent is not systemd/init (master) or sshd (child), or unexpected user",
    },
    "cron": {
        "expected_parents": ["systemd", "init"],
        "expected_user": "root",
        "notes": "Cron daemon. Spawns jobs as the owning user.",
        "suspicious_if": "Parent is not systemd/init",
    },
    "bash": {
        "expected_parents": ["sshd", "login", "su", "sudo", "bash", "tmux", "screen", "gnome-terminal", "konsole", "xterm"],
        "notes": "Interactive shell. Parent should be a login mechanism or terminal.",
        "suspicious_if": "Parent is a web server (apache, nginx, php-fpm) — indicates webshell",
    },
    "sh": {
        "expected_parents": ["bash", "cron", "systemd", "init", "dash"],
        "notes": "POSIX shell. Common in scripts and cron jobs.",
        "suspicious_if": "Parent is a web server or database process — indicates command injection",
    },
    "python": {
        "expected_parents": ["bash", "sh", "cron", "systemd"],
        "notes": "Python interpreter. Common for scripts.",
        "suspicious_if": "Parent is a web server and running interactively, or spawning reverse shells",
    },
    "perl": {
        "expected_parents": ["bash", "sh", "cron"],
        "notes": "Perl interpreter.",
        "suspicious_if": "Spawning network connections or being used for one-liners from web context",
    },
}

# --------------------------------------------------------------------------
# macOS Process Hierarchy
# --------------------------------------------------------------------------

MACOS_HIERARCHY: dict[str, dict] = {
    "launchd": {
        "expected_parents": [],
        "expected_pid": 1,
        "expected_user": "root",
        "notes": "PID 1. macOS init/service manager. Parent of all user-space processes.",
        "suspicious_if": "PID is not 1",
    },
    "kernel_task": {
        "expected_parents": [],
        "expected_pid": 0,
        "expected_user": "root",
        "notes": "PID 0. Kernel. Should never have children that aren't kernel threads.",
        "suspicious_if": "User-space process claims kernel_task as parent",
    },
    "loginwindow": {
        "expected_parents": ["launchd"],
        "expected_user": "root",
        "notes": "Login UI. One per GUI session.",
        "suspicious_if": "Parent is not launchd",
    },
    "WindowServer": {
        "expected_parents": ["launchd"],
        "expected_user": "root/_windowserver",
        "notes": "Display server. Manages all GUI rendering.",
        "suspicious_if": "Parent is not launchd, or running as regular user",
    },
    "Finder": {
        "expected_parents": ["launchd"],
        "expected_user": "<logged-in user>",
        "notes": "macOS file manager/shell.",
        "suspicious_if": "Running as root, or parent is not launchd",
    },
    "osascript": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "AppleScript/JXA interpreter. LOLBIN: Can execute arbitrary code, interact with apps, keylog.",
        "suspicious_if": "Spawned by unexpected parent, running encoded scripts, or making network connections",
    },
    "curl": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "HTTP client. Common LOLBIN for downloading payloads.",
        "suspicious_if": "Downloading to /tmp, piped to sh/bash, or downloading from unusual IPs",
    },
    "python3": {
        "expected_parents": ["bash", "sh", "zsh", "launchd", "cron"],
        "notes": "Python interpreter.",
        "suspicious_if": "Spawned by a GUI app, or executing encoded/obfuscated commands",
    },
    "tccutil": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "TCC database manager. Can reset privacy permissions. LOLBIN.",
        "suspicious_if": "Any execution is suspicious — rarely used legitimately by users",
    },
    "security": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "Keychain/cert tool. Can dump credentials, export certs, manipulate trust.",
        "suspicious_if": "Dumping keychain items, exporting identities, or modifying trust settings",
    },
    "dscl": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "Directory Service command line. Can enumerate/modify users and groups.",
        "suspicious_if": "Creating users, modifying admin group, or reading password policies",
    },
    "defaults": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "Preference manipulation. Can disable security features.",
        "suspicious_if": "Modifying login items, disabling Gatekeeper, or changing quarantine flags",
    },
    "xattr": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "Extended attributes tool. Can remove quarantine flag from downloads.",
        "suspicious_if": "Removing com.apple.quarantine attribute from downloaded files",
    },
    "open": {
        "expected_parents": ["bash", "sh", "zsh", "Finder"],
        "notes": "Opens files/URLs/apps. Can be used to launch apps or open URLs stealthily.",
        "suspicious_if": "Opening unusual URLs or launching apps from /tmp or hidden directories",
    },
    "spctl": {
        "expected_parents": ["bash", "sh", "zsh"],
        "notes": "Gatekeeper policy manager. Can disable Gatekeeper assessment.",
        "suspicious_if": "Disabling Gatekeeper (--master-disable) is highly suspicious",
    },
}

# --------------------------------------------------------------------------
# Combined rules for prompt generation
# --------------------------------------------------------------------------

PROCESS_HIERARCHY_RULES = {
    "windows": WINDOWS_HIERARCHY,
    "linux": LINUX_HIERARCHY,
    "macos": MACOS_HIERARCHY,
}
