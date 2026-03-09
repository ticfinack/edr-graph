"""Diamond Model Investigator: LLM-powered CTI analysis of incidents.

Uses DeepInfra-hosted Gemma3-27B to perform Diamond Model of Intrusion
Analysis on OCSF-normalized telemetry from campaign incidents.
"""

from __future__ import annotations

import json
import logging
import re
import time

logger = logging.getLogger("server.analyzer.diamond")

_SYSTEM_PROMPT = (
    "You are a Senior CTI Analyst. Review the following OCSF-normalized "
    "telemetry, attack chains, and IOCs spanning multiple hosts. Perform a "
    "Diamond Model of Intrusion Analysis on this campaign.\n\n"
    "Respond ONLY with a valid JSON object (no markdown, no commentary) "
    "matching this schema:\n"
    "{\n"
    '  "assessment_verdict": "malicious|suspicious|benign|inconclusive",\n'
    '  "confidence": 0.0-1.0,\n'
    '  "diamond_adversary": {"description": "...", "attribution_indicators": [], "ttps": []},\n'
    '  "diamond_infrastructure": {"description": "...", "c2_indicators": [], "infrastructure_type": "..."},\n'
    '  "diamond_capability": {"description": "...", "tools_observed": [], "techniques": []},\n'
    '  "diamond_victim": {"description": "...", "affected_hosts": [], "affected_users": [], "data_at_risk": "..."},\n'
    '  "tactical_summary": "...",\n'
    '  "recommended_actions": []\n'
    "}"
)

_MAX_CONTEXT_CHARS = 40_000

# Priority order for OCSF event types when truncating
_EVENT_TYPE_PRIORITY = [
    "ProcessActivity",
    "NetworkActivity",
    "FileActivity",
    "DnsActivity",
    "Authentication",
    "RegistryActivity",
]


class DiamondInvestigator:
    """LLM-based Diamond Model analysis of incidents."""

    def __init__(
        self,
        settings_db,
        neo4j_client,
        api_key: str,
        base_url: str,
        model: str,
    ) -> None:
        self._settings_db = settings_db
        self._neo4j = neo4j_client
        self._api_key = api_key
        self._base_url = base_url
        self._model = model
        logger.info("DiamondInvestigator initialized (model=%s)", model)

    def assess_incident(self, incident_id: str) -> dict | None:
        """Run Diamond Model analysis for an incident.

        Returns the parsed assessment dict, or None on failure.
        """
        detail = self._neo4j.get_incident_detail(incident_id)
        if not detail:
            logger.warning("Incident %s not found for Diamond assessment", incident_id)
            return None

        evidence = self._settings_db.get_ocsf_evidence(incident_id)
        context = self._build_context(detail, evidence)

        try:
            import httpx

            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": context},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2000,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
        except Exception:
            logger.exception("LLM API call failed for incident %s", incident_id)
            return None

        content = ""
        prompt_tokens = 0
        completion_tokens = 0
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
            usage = data.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)
        except (KeyError, IndexError):
            logger.warning("Unexpected LLM response structure for %s", incident_id)
            return None

        assessment = _parse_assessment(content)
        if assessment is None:
            logger.warning("Failed to parse Diamond assessment for %s", incident_id)
            return None

        # Attach metadata
        assessment["evidence_count"] = len(evidence)
        assessment["assessed_at"] = int(time.time())

        # Persist to SQLite
        self._settings_db.save_diamond_assessment(
            incident_id,
            json.dumps(assessment),
            self._model,
            prompt_tokens,
            completion_tokens,
        )

        # Also persist on the Neo4j Incident node
        self._neo4j.store_incident_diamond_assessment(incident_id, assessment)

        logger.info(
            "Diamond assessment for %s: verdict=%s confidence=%.2f (evidence=%d)",
            incident_id,
            assessment.get("assessment_verdict", "unknown"),
            assessment.get("confidence", 0),
            len(evidence),
        )
        return assessment

    def _build_context(self, detail: dict, evidence: list[dict]) -> str:
        """Build the LLM context from incident detail and OCSF evidence.

        Enforces a hard character limit with priority-based truncation.
        """
        parts: list[str] = []

        # Incident overview
        overview = (
            f"## Incident Overview\n"
            f"- ID: {detail.get('incident_id', 'unknown')}\n"
            f"- Type: {detail.get('incident_type', 'unknown')}\n"
            f"- Status: {detail.get('status', 'unknown')}\n"
            f"- Source: {detail.get('src_hostname', 'unknown')} ({detail.get('src_agent_id', '')})\n"
            f"- Target: {detail.get('dst_hostname', 'unknown')} ({detail.get('dst_agent_id', '')})\n"
            f"- Pivot IP: {detail.get('pivot_ip', 'none')}\n"
        )

        # Involved hosts
        involved = detail.get("involved_hosts", [])
        if involved:
            overview += f"- Involved hosts: {len(involved)}\n"
            for h in involved[:10]:
                overview += f"  - {h.get('hostname', '?')} ({h.get('agent_id', '')})\n"

        parts.append(overview)

        # Source findings
        source_findings = detail.get("source_findings", [])
        if source_findings:
            sf_text = "## Source Findings\n"
            for sf in source_findings[:20]:
                sf_text += (
                    f"- [{sf.get('severity', '?')}] {sf.get('title', '?')} "
                    f"on {sf.get('hostname', '?')} at {sf.get('timestamp', '?')}\n"
                )
            parts.append(sf_text)

        # Attack chains
        for chain_key, chain_label in [
            ("source_chain", "Source Attack Chain"),
            ("target_chain", "Target Attack Chain"),
        ]:
            chain = detail.get(chain_key, [])
            if chain:
                chain_text = f"## {chain_label}\n"
                for step in chain:
                    chain_text += (
                        f"  {step.get('step_index', '?')}. [{step.get('entity_type', '?')}] "
                        f"{step.get('entity_name', '?')} (pid={step.get('pid', 0)})\n"
                    )
                parts.append(chain_text)

        # Follow-on findings
        follow_on = detail.get("follow_on_findings", [])
        if follow_on:
            fo_text = "## Follow-on Findings\n"
            for fo in follow_on[:20]:
                fo_text += (
                    f"- [{fo.get('severity', '?')}] {fo.get('title', '?')} "
                    f"at {fo.get('timestamp', '?')}\n"
                )
            parts.append(fo_text)

        header_text = "\n".join(parts)
        remaining_budget = _MAX_CONTEXT_CHARS - len(header_text) - 100  # margin

        if remaining_budget <= 0 or not evidence:
            return header_text

        # Group evidence by event type
        by_type: dict[str, list[dict]] = {}
        for ev in evidence:
            et = ev.get("event_type", "Other")
            by_type.setdefault(et, []).append(ev)

        # Priority-based allocation
        ordered_types = []
        for ptype in _EVENT_TYPE_PRIORITY:
            if ptype in by_type:
                ordered_types.append(ptype)
        for et in by_type:
            if et not in ordered_types:
                ordered_types.append(et)

        evidence_parts: list[str] = []
        chars_used = 0

        for et in ordered_types:
            events = by_type[et]
            section = f"\n### {et} ({len(events)} events)\n"
            for ev in events:
                ocsf_raw = ev.get("ocsf_json", "{}")
                # Truncate individual events that are too large
                if len(ocsf_raw) > 2000:
                    ocsf_raw = ocsf_raw[:2000] + "..."
                line = f"- [{ev.get('timestamp', '?')}] {ocsf_raw}\n"
                if chars_used + len(section) + len(line) > remaining_budget:
                    if evidence_parts:
                        section += f"  ... ({len(events)} events, truncated)\n"
                        evidence_parts.append(section)
                    break
                section += line
                chars_used += len(line)
            else:
                evidence_parts.append(section)
                chars_used += len(section)
                continue
            break

        evidence_text = "## OCSF Telemetry Evidence\n" + "".join(evidence_parts)
        return header_text + "\n" + evidence_text


def _parse_assessment(content: str) -> dict | None:
    """Parse LLM response into a structured assessment dict.

    Handles markdown code fences, partial JSON, and whitespace.
    """
    if not content:
        return None

    text = content.strip()

    # Strip markdown code fences
    fence_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # Try direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Try extracting first {...} block
    brace_match = re.search(r'\{.*\}', text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("Could not parse assessment JSON from LLM response")
    return None
