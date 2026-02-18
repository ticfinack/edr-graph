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

    if tools:
        sections.append(_format_tool_instructions(tools))

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


def _format_tool_instructions(tools: list[dict]) -> str:
    tool_names = [t["function"]["name"] for t in tools]
    tool_list = ", ".join(f"`{n}`" for n in tool_names)
    return (
        "## INVESTIGATION TOOLS — YOU MUST USE THESE\n\n"
        f"You have access to the following tools: {tool_list}.\n\n"
        "**IMPORTANT: You MUST investigate before producing findings.** Do NOT skip "
        "straight to your final JSON. For every batch, follow this workflow:\n\n"
        "1. **First**, read the events and identify public IPs, suspicious processes, "
        "and unusual behaviors.\n"
        "2. **Then**, call tools to investigate:\n"
        "   - Call `ip_geolocation` on every public (non-RFC1918) destination IP to "
        "get country, ISP, and hosting/proxy flags.\n"
        "   - Call `reverse_dns` on suspicious IPs to check for known hostnames.\n"
        "   - Call `graph_context_query` on any process or user that looks anomalous "
        "to see their full activity history.\n"
        "   - Call `mitre_attack_lookup` to map suspicious behaviors to ATT&CK "
        "technique IDs (e.g., T1059.004 for shell execution).\n"
        "   - Call `whois_lookup` on suspicious domains.\n"
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
    )


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

## OUTPUT FORMAT

Return ONLY a JSON array of findings. Each finding must have:
- severity: "critical", "high", "medium", "low", or "info"
- title: short description
- description: detailed explanation referencing specific intel (e.g., "svchost.exe \
spawned by explorer.exe violates SANS Hunt Evil parent-child rule")
- affected_entities: array of entity IDs
- evidence_event_ids: array of event queue IDs
- recommendation: actionable next step
- chain: array of {entity_type, entity_id, entity_name, pid} for the event chain
- id: (optional) if updating an existing finding, include its ID

If nothing suspicious is found, return: []"""
