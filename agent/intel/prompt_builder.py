"""Build the threat-intel-enriched system prompt for the LLM analyzer."""

from __future__ import annotations

import platform

from .lolbins import GTFOBINS_BINARIES, LOOBINS_BINARIES, LOLBAS_BINARIES
from .process_hierarchy import LINUX_HIERARCHY, MACOS_HIERARCHY, WINDOWS_HIERARCHY


def build_intel_prompt(tools: list[dict] | None = None) -> str:
    """Build the full system prompt with threat intelligence context.

    Selects platform-relevant intel and combines:
    - Role and task description
    - Process hierarchy rules ("Know Normal")
    - LOLBin/GTFOBin/LOOBin watchlists
    - Tool-use instructions (when tools are provided)
    - Output format instructions

    Args:
        tools: Optional list of OpenAI tool schemas. When provided, a
            tool-use instruction section is appended before the output format.
    """
    system = platform.system()

    sections = [_ROLE_SECTION]

    # Platform-specific hierarchy rules
    if system == "Windows":
        sections.append(_format_hierarchy("Windows", WINDOWS_HIERARCHY))
        sections.append(_format_lolbins("LOLBAS (Windows LOLBins)", LOLBAS_BINARIES))
    elif system == "Linux":
        sections.append(_format_hierarchy("Linux", LINUX_HIERARCHY))
        sections.append(_format_gtfobins())
    elif system == "Darwin":
        sections.append(_format_hierarchy("macOS", MACOS_HIERARCHY))
        sections.append(_format_loobins())
        sections.append(_format_gtfobins())  # GTFOBins apply to macOS too
    else:
        # Include all
        sections.append(_format_hierarchy("Windows", WINDOWS_HIERARCHY))
        sections.append(_format_hierarchy("Linux", LINUX_HIERARCHY))
        sections.append(_format_hierarchy("macOS", MACOS_HIERARCHY))

    sections.append(_IP_INTELLIGENCE_SECTION)

    if tools:
        sections.append(_format_tool_instructions(tools))

    sections.append(_IOC_FEED_SECTION)
    sections.append(_OUTPUT_FORMAT_SECTION)

    return "\n\n".join(sections)


_ROLE_SECTION = """\
You are an expert security analyst performing endpoint detection and response (EDR) \
analysis. You are examining OCSF-normalized events and their graph relationships \
from a live endpoint.

Your analysis MUST be grounded in the threat intelligence provided below. \
Do not hallucinate findings — only flag behavior that violates known-good baselines \
or matches known-bad indicators."""


def _format_hierarchy(platform_name: str, rules: dict[str, dict]) -> str:
    lines = [f"## PROCESS HIERARCHY RULES — {platform_name} (SANS 'Know Normal')"]
    lines.append(
        "If a process violates these parent-child rules, it is HIGHLY suspicious.\n"
    )

    for proc, info in rules.items():
        parents = info.get("expected_parents", [])
        parent_str = ", ".join(parents) if parents else "(none — root process)"
        line = f"- **{proc}**: Expected parent: {parent_str}"
        if info.get("expected_user"):
            line += f" | User: {info['expected_user']}"
        if info.get("suspicious_if"):
            line += f" | ALERT IF: {info['suspicious_if']}"
        lines.append(line)

    return "\n".join(lines)


def _format_lolbins(title: str, binaries: dict) -> str:
    lines = [f"## {title}"]
    lines.append(
        "These are legitimate Windows binaries that attackers abuse. "
        "Flag if used with suspicious arguments or from unexpected contexts.\n"
    )
    for name, info in sorted(binaries.items()):
        funcs = ", ".join(info.get("functions", []))
        desc = info.get("desc", "")
        lines.append(f"- **{name}**: {desc} | Capabilities: {funcs}")
    return "\n".join(lines)


def _format_gtfobins() -> str:
    lines = ["## GTFOBins (Linux/macOS LOLBins)"]
    lines.append(
        "Standard Unix binaries that can be abused for privilege escalation, "
        "file exfiltration, or shell escape. Flag if used in unexpected contexts "
        "(e.g., spawned by a web server, or using SUID).\n"
    )
    # Group by most dangerous capabilities
    dangerous = {
        name: funcs
        for name, funcs in sorted(GTFOBINS_BINARIES.items())
        if any(
            f in funcs
            for f in ("shell", "reverse-shell", "file-upload", "suid", "sudo")
        )
    }
    for name, funcs in dangerous.items():
        lines.append(f"- **{name}**: {', '.join(funcs)}")

    if len(GTFOBINS_BINARIES) > len(dangerous):
        remaining = len(GTFOBINS_BINARIES) - len(dangerous)
        lines.append(
            f"\n({remaining} additional binaries with file-read/file-write/download "
            f"capabilities also tracked)"
        )
    return "\n".join(lines)


def _format_loobins() -> str:
    lines = ["## LOOBins (macOS Living Off the Orchard)"]
    lines.append(
        "macOS-native binaries that attackers abuse. Pay special attention to "
        "these on macOS endpoints.\n"
    )
    for name, info in sorted(LOOBINS_BINARIES.items()):
        funcs = ", ".join(info.get("functions", []))
        desc = info.get("desc", "")
        lines.append(f"- **{name}**: {desc} | Capabilities: {funcs}")
    return "\n".join(lines)


_IP_INTELLIGENCE_SECTION = """\
## IP INTELLIGENCE INTERPRETATION

Pre-enrichment now classifies external IPs into categories. Use these rules \
when interpreting IP connections:

### Classification meanings:
- **known_cloud** (AWS, Azure, GCP, Oracle): EXPECTED infrastructure. Most \
legitimate software connects to cloud services. Only flag if combined with \
OTHER suspicious indicators (unusual process, exfiltration volume, DGA domain, \
unsigned binary).
- **known_cdn** (Cloudflare, Akamai, Fastly): EXPECTED for web traffic. CDN \
IPs serve legitimate content. Not suspicious on their own.
- **known_saas** (Apple, Google, Microsoft, GitHub, Anthropic): EXPECTED for \
normal endpoint operations. A signed Apple/Google/Microsoft process connecting \
to its vendor's cloud is completely NORMAL.
- **known_hosting** (DigitalOcean, Linode, Vultr, Hetzner, OVH): Mildly \
elevated risk but commonly used by legitimate services. Flag ONLY with \
additional indicators (DGA domain, unusual port, suspicious process).
- **known_security** (CrowdStrike, Zscaler): Security vendor infrastructure. \
EXPECTED on managed endpoints. Never flag as malicious.
- **suspicious_hosting**: IP is hosted infrastructure but from an unknown \
provider. Warrants closer inspection but is NOT conclusive evidence of C2.
- **unclassified**: No provider match. Evaluate based on other context.

### RULES:
1. NEVER flag an IP as malicious C2 solely because it is a cloud/CDN/SaaS IP.
2. A signed Apple/Google/Microsoft process connecting to its vendor's cloud \
is EXPECTED behavior — do NOT flag it.
3. When classification is known_cloud, known_cdn, or known_saas, reduce \
severity by at least one level compared to what you would assign for an \
unknown IP with the same behavior.
4. Only escalate a known provider IP if there are MULTIPLE corroborating \
indicators (e.g., unsigned process + DGA domain + known_hosting IP + unusual \
port)."""


def _format_tool_instructions(tools: list[dict]) -> str:
    tool_names = [t["function"]["name"] for t in tools]
    tool_list = ", ".join(f"`{n}`" for n in tool_names)

    # Build Tier 4 investigation guidance if those tools are present
    tier4_section = ""
    tier4_names = {"file_info", "list_directory", "process_info", "netstat_query", "file_hash"}
    active_tier4 = [n for n in tool_names if n in tier4_names]
    if active_tier4:
        tier4_section = (
            "\n\n### Local Investigation Tools\n"
            "You also have safe, read-only tools for inspecting the local host:\n"
        )
        if "file_info" in active_tier4:
            tier4_section += (
                "- `file_info`: Get metadata about suspicious files — permissions, owner, "
                "timestamps, and code signature (macOS). Use this when events reference "
                "a file path you want to verify.\n"
            )
        if "list_directory" in active_tier4:
            tier4_section += (
                "- `list_directory`: Understand what a suspicious process is writing or "
                "reading by listing its working directory or drop locations.\n"
            )
        if "process_info" in active_tier4:
            tier4_section += (
                "- `process_info`: Get live process details — exe path, command line, "
                "network connections, open files, child processes. Use this to verify "
                "if a suspicious process is still running and what it's doing.\n"
            )
        if "netstat_query" in active_tier4:
            tier4_section += (
                "- `netstat_query`: Verify if suspicious connections are still active. "
                "Filter by PID or port to find related network activity.\n"
            )
        if "file_hash" in active_tier4:
            tier4_section += (
                "- `file_hash`: Compute MD5/SHA1/SHA256 for a file, then chain the "
                "SHA256 result to `virustotal_lookup(indicator=sha256, indicator_type='files')` "
                "to check file reputation.\n"
            )
        tier4_section += (
            "\n**Key rule: Don't just recommend investigation — DO IT with these tools.** "
            "If you see a suspicious file path, call `file_info` on it. If you see a "
            "suspicious PID, call `process_info` on it. If you want to check a binary's "
            "reputation, call `file_hash` then `virustotal_lookup`."
        )

    return (
        "## INVESTIGATION TOOLS — YOU MUST USE THESE\n\n"
        f"You have access to the following tools: {tool_list}.\n\n"
        "**IMPORTANT: You MUST investigate before producing findings.** Do NOT skip "
        "straight to your final JSON. For every batch, follow this workflow:\n\n"
        "1. **First**, read the events and identify public IPs, suspicious processes, "
        "and unusual behaviors.\n"
        "2. **Then**, call tools to investigate:\n"
        "   - Call `ip_geolocation` on every public (non-RFC1918) destination IP to "
        "get country, ISP, and hosting/proxy flags. Note: pre-enrichment already "
        "classifies IPs (known_cloud, known_cdn, known_saas, etc.) — check the "
        "classification before flagging an IP as suspicious.\n"
        "   - Call `reverse_dns` on suspicious IPs to check for known hostnames.\n"
        "   - Call `graph_context_query` on any process or user that looks anomalous "
        "to see their full activity history.\n"
        "   - Call `mitre_attack_lookup` to map suspicious behaviors to ATT&CK "
        "technique IDs (e.g., T1059.004 for shell execution).\n"
        "   - Call `whois_lookup` on suspicious domains.\n"
        "   - Use `process_info` and `file_info` to inspect suspicious local entities.\n"
        "   - Use `file_hash` → `virustotal_lookup` to check file reputation.\n"
        "3. **Finally**, after reviewing tool results, produce your findings JSON "
        "with enriched descriptions that include concrete data from your lookups "
        "(ISP names, countries, abuse scores, MITRE technique IDs).\n\n"
        "Rules:\n"
        "- Do NOT look up RFC1918 private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) "
        "— they will fail.\n"
        "- If multiple events reference the same IP, only look it up once.\n"
        "- You have up to 5 rounds of tool calls. Use them.\n"
        "- A finding that says 'investigate this IP' without having called "
        "`ip_geolocation` on it is INCOMPLETE. Do the investigation yourself."
        + tier4_section
    )


_IOC_FEED_SECTION = """\
## IOC FEED MATCHING

Events matching known-bad IOC feeds (Feodo Tracker, ThreatFox, URLhaus, MalBazaar) \
are flagged as CRITICAL automatically by the processor pipeline. These matches appear \
as findings with titles starting with "Known Botnet C2 IP Detected", "Known Malicious \
Domain Detected", or "Known Malware Hash Detected".

When you see pre-enrichment data showing "IOC FEED MATCH", this means the indicator \
was found in a threat intelligence feed. Provide additional behavioral context:
- What process initiated the connection?
- Is the process expected to make such connections?
- Are there other related indicators in this batch?
- What MITRE ATT&CK techniques does this activity map to?

Do NOT duplicate the IOC feed finding — instead reference it and add behavioral analysis."""

_OUTPUT_FORMAT_SECTION = """\
## ANALYSIS INSTRUCTIONS

For each batch of events, check:
1. **Process hierarchy violations**: Does any process have an unexpected parent? \
(Use the rules above)
2. **LOLBin/GTFOBin/LOOBin abuse**: Is a known dual-use binary being used with \
suspicious arguments, from an unexpected parent, or making unusual network connections?
3. **Anomalous network connections**: Unexpected destination IPs, unusual ports, \
or processes that shouldn't make network connections.
4. **Lateral movement**: SSH/RDP/WinRM from unexpected sources or to unexpected targets.
5. **Privilege escalation**: sudo/su/runas from unexpected contexts, SUID abuse.
6. **Data exfiltration**: Bulk data transfer, DNS tunneling indicators, \
connections to known-bad infrastructure.

IMPORTANT: Routine system behavior (launchd spawning services, expected daemons, \
WebKit making HTTPS connections) is NORMAL — do NOT flag it. Only flag deviations \
from the baselines above.

## FINDING ACCUMULATION

If you see existing findings for processes in this batch, you may update them \
instead of creating new findings. To update, return the same finding ID in your \
response with the updated description and any new evidence_event_ids. Escalate \
severity if the new evidence warrants it.

If a process already has a finding but the new events are unrelated to that \
finding, create a new finding instead.

## PID ATTRIBUTION

DNS events come from mDNSResponder (PID 0) and file events from FSEvents (PID 0). \
These are system-level collectors — the actual originating process PID is NOT in those \
events. When creating findings, use the process PID from process_start or network events \
in the same batch, NOT PID 0. If a finding involves DNS or file activity, attribute it \
to the process that initiated the network connection or was active at that time. \
Do NOT include PID 0 in affected_pids.

## OUTPUT FORMAT

Return ONLY a JSON array of findings. Each finding must have:
- severity: "critical", "high", "medium", "low", or "info"
- title: short description
- description: detailed explanation referencing specific intel (e.g., "svchost.exe \
spawned by explorer.exe violates SANS Hunt Evil parent-child rule")
- affected_entities: array of entity IDs
- affected_pids: array of integer PIDs (>0) for processes involved in this finding
- evidence_event_ids: array of event queue IDs
- recommendation: actionable next step
- chain: array of {entity_type, entity_id, entity_name, pid} for the event chain
- iocs: object with optional keys:
  - domains: array of FQDNs observed (e.g., ["evil.com", "c2.example.org"])
  - ips: array of IP addresses (e.g., ["1.2.3.4"])
  - files: array of file paths (e.g., ["/tmp/payload.sh"])
  - urls: array of full URLs if known
- id: (optional) if updating an existing finding, include its ID

If nothing suspicious is found, return: []"""
