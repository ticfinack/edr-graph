"""Application allowlist: curated database of known macOS apps and expected network behavior."""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
from dataclasses import dataclass, field

from agent.enrichment.process_identity import ProcessIdentity

logger = logging.getLogger(__name__)


@dataclass
class NetworkPattern:
    """A network behavior pattern expected for an application."""

    pattern_type: str  # "localhost_ipc", "domain", "ip_range", "any_outbound"
    value: str  # glob pattern for domain, CIDR for ip_range, "" for localhost_ipc
    ports: list[int] = field(default_factory=list)  # empty = any port
    description: str = ""


@dataclass
class AllowlistEntry:
    """A known application and its expected network behavior."""

    bundle_id: str
    app_name: str
    expected_network: list[NetworkPattern] = field(default_factory=list)
    description: str = ""
    category: str = ""  # "system", "development", "browser", "communication", "security"


@dataclass
class AllowlistResult:
    """Result of checking a connection against the allowlist."""

    is_allowed: bool = False
    matched_entry: AllowlistEntry | None = None
    matched_pattern: NetworkPattern | None = None
    explanation: str = ""
    confidence: str = "none"  # "high", "medium", "low", "none"
    risk_reduction: str = ""  # e.g. "Known Apple system service"


# Built-in allowlist of known macOS applications
BUILTIN_ALLOWLIST: list[AllowlistEntry] = [
    # -- Apple system services --
    AllowlistEntry(
        bundle_id="com.apple.Safari",
        app_name="Safari",
        expected_network=[
            NetworkPattern("any_outbound", "", ports=[80, 443], description="Web browsing"),
        ],
        description="Apple web browser",
        category="browser",
    ),
    AllowlistEntry(
        bundle_id="com.apple.mDNSResponder",
        app_name="mDNSResponder",
        expected_network=[
            NetworkPattern("localhost_ipc", "", description="DNS resolution IPC"),
            NetworkPattern("any_outbound", "", ports=[53, 5353], description="DNS queries"),
        ],
        description="macOS DNS resolver",
        category="system",
    ),
    AllowlistEntry(
        bundle_id="com.apple.nsurlsessiond",
        app_name="nsurlsessiond",
        expected_network=[
            NetworkPattern("any_outbound", "", ports=[443], description="Background URL sessions"),
            NetworkPattern("domain", "*.apple.com", description="Apple services"),
            NetworkPattern("domain", "*.icloud.com", description="iCloud sync"),
            NetworkPattern("ip_range", "17.0.0.0/8", description="Apple IP range"),
        ],
        description="macOS URL session daemon",
        category="system",
    ),
    AllowlistEntry(
        bundle_id="com.apple.cloudd",
        app_name="cloudd",
        expected_network=[
            NetworkPattern("domain", "*.icloud.com", description="iCloud sync"),
            NetworkPattern("domain", "*.apple.com", description="Apple services"),
            NetworkPattern("ip_range", "17.0.0.0/8", description="Apple IP range"),
        ],
        description="iCloud Drive daemon",
        category="system",
    ),
    # -- Development tools --
    AllowlistEntry(
        bundle_id="dev.kdrag0n.OrbStack",
        app_name="OrbStack",
        expected_network=[
            NetworkPattern("localhost_ipc", "", description="Docker/VM IPC"),
            NetworkPattern("domain", "*.docker.io", description="Docker registry"),
            NetworkPattern("domain", "*.docker.com", description="Docker Hub"),
            NetworkPattern("domain", "*.orbstack.dev", description="OrbStack updates"),
        ],
        description="Docker & Linux VM manager",
        category="development",
    ),
    AllowlistEntry(
        bundle_id="com.docker.docker",
        app_name="Docker Desktop",
        expected_network=[
            NetworkPattern("localhost_ipc", "", description="Docker daemon IPC"),
            NetworkPattern("domain", "*.docker.io", description="Docker registry"),
            NetworkPattern("domain", "*.docker.com", description="Docker Hub"),
        ],
        description="Docker Desktop for Mac",
        category="development",
    ),
    AllowlistEntry(
        bundle_id="com.microsoft.VSCode",
        app_name="Visual Studio Code",
        expected_network=[
            NetworkPattern("localhost_ipc", "", description="Extension host IPC"),
            NetworkPattern("domain", "*.vscode-cdn.net", description="Extension downloads"),
            NetworkPattern("domain", "*.visualstudio.com", description="Marketplace"),
            NetworkPattern("domain", "*.github.com", description="GitHub integration"),
        ],
        description="Code editor",
        category="development",
    ),
    AllowlistEntry(
        bundle_id="com.googlecode.iterm2",
        app_name="iTerm2",
        expected_network=[
            NetworkPattern("localhost_ipc", "", description="Terminal IPC"),
            NetworkPattern("domain", "iterm2.com", description="Update checks"),
        ],
        description="Terminal emulator",
        category="development",
    ),
    # -- Browsers --
    AllowlistEntry(
        bundle_id="com.google.Chrome",
        app_name="Google Chrome",
        expected_network=[
            NetworkPattern("any_outbound", "", ports=[80, 443], description="Web browsing"),
            NetworkPattern("localhost_ipc", "", description="Helper IPC"),
        ],
        description="Google Chrome browser",
        category="browser",
    ),
    AllowlistEntry(
        bundle_id="org.mozilla.firefox",
        app_name="Firefox",
        expected_network=[
            NetworkPattern("any_outbound", "", ports=[80, 443], description="Web browsing"),
        ],
        description="Mozilla Firefox browser",
        category="browser",
    ),
    # -- Communication --
    AllowlistEntry(
        bundle_id="com.tinyspeck.slackmacgap",
        app_name="Slack",
        expected_network=[
            NetworkPattern("domain", "*.slack.com", description="Slack API"),
            NetworkPattern("domain", "*.slack-edge.com", description="Slack CDN"),
            NetworkPattern("any_outbound", "", ports=[443], description="Slack HTTPS"),
        ],
        description="Team communication",
        category="communication",
    ),
    AllowlistEntry(
        bundle_id="us.zoom.xos",
        app_name="Zoom",
        expected_network=[
            NetworkPattern("domain", "*.zoom.us", description="Zoom services"),
            NetworkPattern("domain", "*.zoomgov.com", description="Zoom Gov"),
            NetworkPattern("any_outbound", "", ports=[443, 8801, 8802], description="Zoom media"),
        ],
        description="Video conferencing",
        category="communication",
    ),
    # -- Cloud/Productivity --
    AllowlistEntry(
        bundle_id="com.getdropbox.dropbox",
        app_name="Dropbox",
        expected_network=[
            NetworkPattern("domain", "*.dropbox.com", description="Dropbox sync"),
            NetworkPattern("domain", "*.dropboxapi.com", description="Dropbox API"),
            NetworkPattern("localhost_ipc", "", description="Dropbox local sync"),
        ],
        description="Cloud file sync",
        category="cloud",
    ),
    # -- Security --
    AllowlistEntry(
        bundle_id="com.crowdstrike.falcon.Agent",
        app_name="CrowdStrike Falcon",
        expected_network=[
            NetworkPattern("domain", "*.crowdstrike.com", description="Falcon cloud"),
            NetworkPattern("any_outbound", "", ports=[443], description="Sensor communication"),
        ],
        description="Endpoint protection agent",
        category="security",
    ),
    AllowlistEntry(
        bundle_id="com.apple.XProtect",
        app_name="XProtect",
        expected_network=[
            NetworkPattern("domain", "*.apple.com", description="Signature updates"),
            NetworkPattern("ip_range", "17.0.0.0/8", description="Apple IP range"),
        ],
        description="macOS built-in antivirus",
        category="security",
    ),
]

# Index by bundle_id for fast lookup
_BUNDLE_INDEX: dict[str, AllowlistEntry] = {e.bundle_id: e for e in BUILTIN_ALLOWLIST}

# Index by process name (lowercase) for fallback
_NAME_INDEX: dict[str, AllowlistEntry] = {
    e.app_name.lower(): e for e in BUILTIN_ALLOWLIST
}


def _rebuild_indexes(entries: list[AllowlistEntry]) -> None:
    """Rebuild lookup indexes after adding custom entries."""
    _BUNDLE_INDEX.clear()
    _NAME_INDEX.clear()
    for e in entries:
        _BUNDLE_INDEX[e.bundle_id] = e
        _NAME_INDEX[e.app_name.lower()] = e


def load_custom_entries(custom_entries: list[dict]) -> None:
    """Load user-defined allowlist entries from config."""
    all_entries = list(BUILTIN_ALLOWLIST)
    for entry_dict in custom_entries:
        try:
            patterns = []
            for p in entry_dict.get("expected_network", []):
                patterns.append(NetworkPattern(
                    pattern_type=p.get("pattern_type", "domain"),
                    value=p.get("value", ""),
                    ports=p.get("ports", []),
                    description=p.get("description", ""),
                ))
            entry = AllowlistEntry(
                bundle_id=entry_dict.get("bundle_id", ""),
                app_name=entry_dict.get("app_name", ""),
                expected_network=patterns,
                description=entry_dict.get("description", ""),
                category=entry_dict.get("category", "custom"),
            )
            all_entries.append(entry)
        except Exception:
            logger.debug("Failed to parse custom allowlist entry", exc_info=True)

    _rebuild_indexes(all_entries)
    logger.info("Allowlist loaded: %d entries (%d custom)", len(all_entries), len(custom_entries))


def check_allowlist(
    process_identity: ProcessIdentity | None,
    dest_ip: str = "",
    dest_port: int = 0,
    tls_sni: str | None = None,
    http_host: str | None = None,
    process_name: str = "",
) -> AllowlistResult:
    """Check if a connection matches the allowlist.

    Matches by bundle_id (high confidence) or process_name (medium confidence).
    Returns AllowlistResult with match details.
    """
    result = AllowlistResult()

    # 1. Try to match by bundle_id (high confidence)
    entry = None
    confidence = "none"
    if process_identity and process_identity.bundle_id:
        entry = _BUNDLE_INDEX.get(process_identity.bundle_id)
        if entry:
            confidence = "high"

    # 2. Fallback to process name (medium confidence)
    if not entry:
        name = ""
        if process_identity and process_identity.name:
            name = process_identity.name
        elif process_name:
            name = process_name

        if name:
            entry = _NAME_INDEX.get(name.lower())
            if entry:
                confidence = "medium"

    if not entry:
        result.explanation = "Unknown application — not in allowlist"
        return result

    result.confidence = confidence

    # 3. Check connection against entry's expected_network patterns
    for pattern in entry.expected_network:
        matched = _match_pattern(pattern, dest_ip, dest_port, tls_sni, http_host)
        if matched:
            result.is_allowed = True
            result.matched_entry = entry
            result.matched_pattern = pattern
            result.explanation = (
                f"Allowed: {entry.app_name} — {pattern.description} "
                f"(confidence: {confidence})"
            )
            result.risk_reduction = f"Known {entry.category} application: {entry.app_name}"
            return result

    # Known app but unexpected pattern
    result.matched_entry = entry
    result.explanation = (
        f"Known app {entry.app_name} with unexpected network behavior to "
        f"{dest_ip}:{dest_port} (SNI: {tls_sni or 'N/A'})"
    )
    return result


def _match_pattern(
    pattern: NetworkPattern,
    dest_ip: str,
    dest_port: int,
    tls_sni: str | None,
    http_host: str | None,
) -> bool:
    """Check if a connection matches a specific NetworkPattern."""
    if pattern.pattern_type == "localhost_ipc":
        if dest_ip in ("127.0.0.1", "::1", "localhost") or dest_ip.startswith("127."):
            if pattern.ports and dest_port not in pattern.ports:
                return False
            return True
        return False

    elif pattern.pattern_type == "domain":
        hostname = tls_sni or http_host
        if hostname and fnmatch.fnmatch(hostname, pattern.value):
            return True
        return False

    elif pattern.pattern_type == "ip_range":
        try:
            network = ipaddress.ip_network(pattern.value, strict=False)
            addr = ipaddress.ip_address(dest_ip)
            if addr in network:
                return True
        except ValueError:
            pass
        return False

    elif pattern.pattern_type == "any_outbound":
        if pattern.ports:
            return dest_port in pattern.ports
        return True

    return False
