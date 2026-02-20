"""Batch security analysis via DeepInfra Gemma3-27B."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import time
import uuid
from datetime import datetime

import kuzu
from openai import OpenAI

from agent import metrics
from agent.config import Settings
from agent.enrichment.ip_reputation import classify_ip
from agent.graph.queries import build_attack_chain, serialize_attack_chain
from agent.intel.prompt_builder import build_intel_prompt
from agent.processor.graph_builder import GraphBuilder
from agent.schema.graph_types import ChainStep, IpNode, SecurityFinding
from agent.schema.ocsf_types import (
    Authentication,
    DnsActivity,
    FileActivity,
    NetworkActivity,
    OcsfEvent,
    ProcessActivity,
    RegistryActivity,
)

from .tool_cache import ToolCache
from .tools import ToolExecutor, get_active_tools

logger = logging.getLogger(__name__)


class LlmAnalyzer:
    """Performs batch security analysis using Gemma3-27B via DeepInfra."""

    def __init__(self, settings: Settings, kuzu_db: kuzu.Database, queue=None, ioc_db=None) -> None:
        self._settings = settings
        self._kuzu_db = kuzu_db
        self._queue = queue
        self._ioc_db = ioc_db

        # Build active tools list
        if settings.tool_use_enabled:
            self._tools = get_active_tools(settings)
        else:
            self._tools = []

        self._system_prompt = build_intel_prompt(
            tools=self._tools if self._tools else None
        )
        logger.info(
            "Intel prompt built: ~%d chars, %d tools active",
            len(self._system_prompt),
            len(self._tools),
        )
        self._client: OpenAI | None = None
        if settings.deepinfra_api_key:
            self._client = OpenAI(
                api_key=settings.deepinfra_api_key,
                base_url=settings.deepinfra_base_url,
            )

    def analyze_batch(
        self, events: list[tuple[int, OcsfEvent]]
    ) -> list[SecurityFinding]:
        """Analyze a batch of novel OCSF events. Returns security findings."""
        if not events:
            return []
        if not self._client:
            logger.warning("No DeepInfra API key configured, skipping LLM analysis")
            return []

        # Build context and pre-enrich with tool lookups
        batch_context = self._build_batch_context(events)
        if not batch_context:
            return []

        if self._tools:
            enrichment = self._pre_enrich(events)
            if enrichment:
                batch_context += "\n\n" + enrichment

        try:
            if self._tools:
                return self._analyze_with_tools(batch_context, events)
            else:
                return self._analyze_single_shot(batch_context, events)
        except Exception:
            logger.exception("LLM analysis failed")
            return []

    def _analyze_single_shot(
        self, batch_context: str, events: list[tuple[int, OcsfEvent]]
    ) -> list[SecurityFinding]:
        """Original single-call path (no tools)."""
        t0 = time.monotonic()
        response = self._client.chat.completions.create(
            model=self._settings.deepinfra_model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": batch_context},
            ],
            temperature=0.1,
        )
        metrics.llm_call_latency.observe(time.monotonic() - t0)
        content = response.choices[0].message.content
        findings = self._parse_findings(content, events)
        for f in findings:
            metrics.llm_verdicts.labels(severity=f.severity).inc()
        return findings

    def _analyze_with_tools(
        self, batch_context: str, events: list[tuple[int, OcsfEvent]]
    ) -> list[SecurityFinding]:
        """Tool-use loop: LLM can call tools up to max_iterations rounds."""
        cache = ToolCache()
        executor = ToolExecutor(self._settings, self._kuzu_db, cache)
        max_iter = self._settings.tool_use_max_iterations

        messages = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": batch_context},
        ]

        for iteration in range(1, max_iter + 1):
            t0 = time.monotonic()
            response = self._client.chat.completions.create(
                model=self._settings.deepinfra_model,
                messages=messages,
                tools=self._tools,
                temperature=0.1,
            )
            metrics.llm_call_latency.observe(time.monotonic() - t0)
            choice = response.choices[0]

            # If model finished without tool calls, parse the result
            if choice.finish_reason == "stop":
                logger.info(
                    "Tool-use loop completed after %d iteration(s), "
                    "cache: {entries: %d}",
                    iteration,
                    cache.size,
                )
                findings = self._parse_findings(choice.message.content, events)
                for f in findings:
                    metrics.llm_verdicts.labels(severity=f.severity).inc()
                return findings

            # Process tool calls
            tool_calls = choice.message.tool_calls
            if not tool_calls:
                # No tool calls and not "stop" — treat as final answer
                logger.info(
                    "Tool-use loop completed after %d iteration(s) (no tool calls), "
                    "cache: {entries: %d}",
                    iteration,
                    cache.size,
                )
                findings = self._parse_findings(choice.message.content or "[]", events)
                for f in findings:
                    metrics.llm_verdicts.labels(severity=f.severity).inc()
                return findings

            # Append assistant message with tool_calls
            messages.append(choice.message)

            # Execute each tool call and append results
            for tc in tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}
                logger.debug(
                    "Tool call [iter %d]: %s(%s)", iteration, fn_name, fn_args
                )
                result = executor.execute(fn_name, fn_args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        # Exhausted iterations — force a final answer without tools
        logger.warning(
            "Tool-use loop exhausted %d iterations, forcing final answer. "
            "cache: {entries: %d}",
            max_iter,
            cache.size,
        )
        messages.append({
            "role": "user",
            "content": (
                "You have used all available investigation rounds. "
                "Please produce your final findings JSON now."
            ),
        })
        t0 = time.monotonic()
        response = self._client.chat.completions.create(
            model=self._settings.deepinfra_model,
            messages=messages,
            temperature=0.1,
        )
        metrics.llm_call_latency.observe(time.monotonic() - t0)
        findings = self._parse_findings(response.choices[0].message.content, events)
        for f in findings:
            metrics.llm_verdicts.labels(severity=f.severity).inc()
        return findings

    def _pre_enrich(self, events: list[tuple[int, OcsfEvent]]) -> str:
        """Auto-enrich: look up IPs, processes, and MITRE mappings before LLM call.

        For every batch, automatically:
        1. Geolocation + reverse DNS on all public destination IPs
        2. Graph context query on unique processes (recent connections, history)
        3. MITRE ATT&CK lookup for process behaviors (shell exec, LOLBin use, etc.)
        """
        cache = ToolCache()
        executor = ToolExecutor(self._settings, self._kuzu_db, cache)
        sections: list[str] = []

        # --- 1. IP intelligence ---
        public_ips: set[str] = set()
        for _, event in events:
            if isinstance(event, NetworkActivity) and event.dst_endpoint:
                ip = event.dst_endpoint.ip
                if ip:
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            public_ips.add(ip)
                    except ValueError:
                        pass
            if isinstance(event, Authentication) and event.src_endpoint:
                ip = event.src_endpoint.ip
                if ip:
                    try:
                        if not ipaddress.ip_address(ip).is_private:
                            public_ips.add(ip)
                    except ValueError:
                        pass

        if public_ips:
            try:
                graph_builder = GraphBuilder(self._kuzu_db)
            except Exception:
                graph_builder = None
            lines = ["## Pre-enrichment: IP intelligence\n"]
            for ip in sorted(public_ips):
                lines.append(f"### {ip}")
                geo_raw = executor.execute("ip_geolocation", {"ip": ip})
                lines.append(f"Geolocation: {geo_raw}")
                rdns_raw = executor.execute("reverse_dns", {"ip": ip})
                rdns_str = None
                if rdns_raw and rdns_raw != "null" and "error" not in rdns_raw.lower():
                    rdns_str = rdns_raw.strip().strip('"')
                lines.append(f"Reverse DNS: {rdns_raw}")

                # Parse GeoIP JSON and classify
                geo_data = {}
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    geo_data = json.loads(geo_raw) if geo_raw else {}

                if geo_data:
                    reputation = classify_ip(geo_data, rdns_str)
                    lines.append(
                        f"Classification: {reputation.classification.value} "
                        f"(provider: {reputation.provider_name or 'unknown'})"
                    )

                    # Persist enrichment to graph
                    ip_node = IpNode(
                        id=ip,
                        address=ip,
                        is_private=False,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        country=reputation.country,
                        city=reputation.city,
                        isp=reputation.isp,
                        org=reputation.org,
                        asn=reputation.asn,
                        is_hosting=reputation.is_hosting,
                        is_proxy=reputation.is_proxy,
                        classification=reputation.classification.value,
                        provider_name=reputation.provider_name,
                        reverse_dns=reputation.reverse_dns or "",
                    )
                    if graph_builder:
                        try:
                            graph_builder.upsert_ip_enrichment(ip_node)
                        except Exception:
                            logger.debug("Failed to persist IP enrichment for %s", ip, exc_info=True)

                lines.append("")
            if graph_builder:
                graph_builder.close()
            sections.append("\n".join(lines))

        # --- 2. Process intelligence ---
        process_names: set[str] = set()
        process_cmds: dict[str, str] = {}  # name -> cmd_line
        users: set[str] = set()
        for _, event in events:
            if isinstance(event, ProcessActivity):
                name = event.process.name
                if name:
                    process_names.add(name)
                    if event.process.cmd_line:
                        process_cmds[name] = event.process.cmd_line
                if event.actor:
                    users.add(event.actor.user.name)
            if isinstance(event, NetworkActivity) and event.process and event.process.name:
                process_names.add(event.process.name)

        if process_names:
            lines = ["## Pre-enrichment: Process intelligence\n"]
            for proc in sorted(process_names):
                lines.append(f"### Process: {proc}")
                # Graph context: what has this process been doing?
                ctx = executor.execute(
                    "graph_context_query",
                    {"entity_type": "process", "entity_id": proc},
                )
                lines.append(f"Graph history: {ctx}")
                # MITRE lookup for the process name
                mitre = executor.execute(
                    "mitre_attack_lookup", {"query": proc}
                )
                if '"error"' not in mitre:
                    lines.append(f"MITRE ATT&CK: {mitre}")
                # If we have a command line, also look up key commands in it
                cmd = process_cmds.get(proc, "")
                if cmd:
                    # Extract interesting keywords from command line
                    for keyword in ("curl", "wget", "ssh", "nc", "base64",
                                    "chmod", "chown", "sudo", "osascript",
                                    "python", "perl", "ruby", "shell",
                                    "keychain", "security", "launchctl"):
                        if keyword in cmd.lower() and keyword != proc.lower():
                            mitre_cmd = executor.execute(
                                "mitre_attack_lookup", {"query": keyword}
                            )
                            if '"error"' not in mitre_cmd:
                                lines.append(
                                    f"MITRE ATT&CK ({keyword} in cmd): {mitre_cmd}"
                                )
                            break  # one keyword match is enough
                lines.append("")
            sections.append("\n".join(lines))

        # --- 3. User intelligence ---
        if users:
            lines = ["## Pre-enrichment: User intelligence\n"]
            for user in sorted(users):
                ctx = executor.execute(
                    "graph_context_query",
                    {"entity_type": "user", "entity_id": user},
                )
                lines.append(f"### User: {user}")
                lines.append(f"Graph history: {ctx}")
                lines.append("")
            sections.append("\n".join(lines))

        # --- 4. IOC feed intelligence ---
        ioc_matches_found = 0
        if self._ioc_db is not None:
            ioc_lines = ["## Pre-enrichment: IOC feed intelligence\n"]
            has_match = False

            for ip in sorted(public_ips):
                match = self._ioc_db.check_ip(ip)
                if match:
                    ioc_lines.append(
                        f"IOC FEED MATCH: {ip} — {match.feed_name}: {match.description}"
                    )
                    has_match = True
                    ioc_matches_found += 1

            # Check domains from DnsActivity events
            dns_domains: set[str] = set()
            for _, event in events:
                if isinstance(event, DnsActivity) and event.query_domain:
                    dns_domains.add(event.query_domain)

            for domain in sorted(dns_domains):
                match = self._ioc_db.check_domain(domain)
                if match:
                    ioc_lines.append(
                        f"IOC FEED MATCH: {domain} — {match.feed_name}: {match.description}"
                    )
                    has_match = True
                    ioc_matches_found += 1

            if has_match:
                ioc_lines.append("")
                sections.append("\n".join(ioc_lines))

        if not sections:
            return ""

        enrichment = "\n\n".join(sections)
        logger.info(
            "Pre-enriched %d IP(s), %d process(es), %d user(s), "
            "%d IOC feed match(es), cache: {entries: %d}",
            len(public_ips),
            len(process_names),
            len(users),
            ioc_matches_found,
            cache.size,
        )
        return enrichment

    def _build_batch_context(self, events: list[tuple[int, OcsfEvent]]) -> str:
        """Build the context string for the LLM, including attack chain context."""
        lines = ["## Events in this batch\n"]

        for event_id, event in events:
            lines.append(f"### Event {event_id}")
            lines.append(f"Type: {type(event).__name__}")
            lines.append(f"Time: {event.time.isoformat()}")

            if isinstance(event, ProcessActivity):
                lines.append(f"Process: {event.process.name} (PID {event.process.pid})")
                if event.process.cmd_line:
                    lines.append(f"Command: {event.process.cmd_line}")
                if event.actor:
                    lines.append(f"User: {event.actor.user.name}")
            elif isinstance(event, NetworkActivity):
                if event.process:
                    lines.append(f"Process: {event.process.name}")
                if event.dst_endpoint:
                    lines.append(
                        f"Destination: {event.dst_endpoint.ip}:{event.dst_endpoint.port}"
                    )
                # Add enrichment context for network events
                self._append_network_enrichment(lines, event)
            elif isinstance(event, Authentication):
                lines.append(f"User: {event.user.name}")
                lines.append(f"Status: {'Success' if event.status_id == 1 else 'Failure'}")
                if event.src_endpoint:
                    lines.append(f"Source IP: {event.src_endpoint.ip}")
            elif isinstance(event, DnsActivity):
                if event.process:
                    lines.append(f"Process: {event.process.name}")
                lines.append(f"DNS query: {event.query_domain}")
                if event.resolved_ips:
                    lines.append(f"Resolved to: {', '.join(event.resolved_ips)}")
            elif isinstance(event, FileActivity):
                if event.process:
                    lines.append(f"Process: {event.process.name}")
                op_names = {1: "Create", 2: "Read", 3: "Modify", 4: "Delete"}
                lines.append(f"File {op_names.get(event.activity_id, 'Op')}: {event.file_path}")
            elif isinstance(event, RegistryActivity):
                if event.process:
                    lines.append(f"Process: {event.process.name}")
                op_names = {1: "Create", 3: "Modify", 4: "Delete"}
                lines.append(
                    f"Registry {op_names.get(event.activity_id, 'Op')}: {event.reg_path}"
                )
                if event.reg_value_name:
                    lines.append(f"Value: {event.reg_value_name} = {event.reg_value_data}")
            lines.append("")

        # Build attack chain context for processes in this batch
        attack_chains = self._build_attack_chain_context(events)
        if attack_chains:
            lines.append("## Attack chain context\n")
            lines.append(attack_chains)

        # Add bounded graph context (legacy, for user/process history)
        graph_context = self._get_graph_context(events)
        if graph_context:
            lines.append("## Recent graph context (last 20 per entity)\n")
            lines.append(graph_context)

        # Add existing findings for processes in this batch
        if self._queue:
            batch_pids = self._collect_batch_pids(events)
            if batch_pids:
                try:
                    existing_findings = self._queue.get_findings_for_pids(batch_pids)
                    if existing_findings:
                        lines.append("\n## Existing findings for processes in this batch\n")
                        for f in existing_findings[:5]:
                            lines.append(f"### Finding: {f.title} [{f.severity}] (ID: {f.id})")
                            lines.append(f"PIDs: {f.affected_pids}")
                            lines.append(f"Evidence so far: event IDs {f.evidence_event_ids}")
                            lines.append(f"Description: {f.description[:300]}")
                            lines.append("")
                except Exception:
                    logger.debug("Failed to fetch existing findings for batch PIDs", exc_info=True)

        return "\n".join(lines)

    def _append_network_enrichment(
        self, lines: list[str], event: NetworkActivity
    ) -> None:
        """Append process identity and allowlist context for a NetworkActivity event."""
        try:
            if not event.process or not event.dst_endpoint:
                return

            # Process identity enrichment
            identity = None
            if event.process.exe_path:
                try:
                    from agent.enrichment.process_identity import get_process_identity
                    identity = get_process_identity(event.process.pid, event.process.exe_path)
                    if identity and identity.code_signed:
                        notarized = "notarized" if identity.is_notarized else "not notarized"
                        lines.append(
                            f"Identity: {identity.bundle_id or 'N/A'}, "
                            f"signed by \"{identity.signing_authority or 'unknown'}\", "
                            f"{notarized}"
                        )
                except ImportError:
                    pass

            # Allowlist check
            if self._settings.allowlist_enabled:
                try:
                    from agent.enrichment.application_allowlist import check_allowlist
                    result = check_allowlist(
                        process_identity=identity,
                        dest_ip=event.dst_endpoint.ip or "",
                        dest_port=event.dst_endpoint.port or 0,
                        process_name=event.process.name,
                    )
                    if result.is_allowed:
                        lines.append(
                            f"Allowlist: MATCH — \"{result.matched_pattern.description}\" "
                            f"({result.risk_reduction})"
                        )
                    elif result.matched_entry:
                        lines.append(
                            f"Allowlist: NO MATCH — {result.explanation}"
                        )
                except ImportError:
                    pass

            # Connection metadata (SNI, JA3) from SQLite
            with contextlib.suppress(Exception):
                self._append_connection_metadata(lines, event)

        except Exception:
            logger.debug("Network enrichment failed", exc_info=True)

    def _append_connection_metadata(
        self, lines: list[str], event: NetworkActivity
    ) -> None:
        """Look up connection metadata (SNI, JA3) from SQLite for this event."""
        if not event.dst_endpoint:
            return

        try:
            import sqlite3

            from agent.collectors.connection_metadata import get_connection_metadata

            db_path = str(self._settings.db_path)
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row

            # Check if connection_metadata table exists
            table_check = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='connection_metadata'"
            ).fetchone()
            if not table_check:
                conn.close()
                return

            rows = get_connection_metadata(conn, pid=event.process.pid if event.process else None, hours=1)
            conn.close()

            for row in rows[:1]:  # Just the most recent match
                sni = row.get("tls_sni")
                ja3 = row.get("ja3_hash")
                if sni:
                    lines.append(f"TLS SNI: {sni}")
                if ja3:
                    from agent.collectors.connection_metadata import KNOWN_JA3
                    ja3_info = KNOWN_JA3.get(ja3)
                    if ja3_info:
                        lines.append(f"JA3: {ja3} ({ja3_info['app']}, risk: {ja3_info['risk']})")
                    else:
                        lines.append(f"JA3: {ja3}")
        except Exception:
            pass

    def _build_attack_chain_context(self, events: list[tuple[int, OcsfEvent]]) -> str:
        """Build attack chain context for processes in this batch."""
        conn = kuzu.Connection(self._kuzu_db)
        seen_pids: set[int] = set()
        sections: list[str] = []

        for _, event in events:
            pid = None
            if isinstance(event, ProcessActivity) or (
                isinstance(event, (NetworkActivity, DnsActivity, FileActivity, RegistryActivity)) and event.process
            ):
                pid = event.process.pid

            if pid and pid not in seen_pids:
                seen_pids.add(pid)
                chain = build_attack_chain(conn, pid)
                serialized = serialize_attack_chain(chain)
                if serialized.strip():
                    sections.append(f"### PID {pid}\n{serialized}")

        return "\n\n".join(sections)

    def _get_graph_context(self, events: list[tuple[int, OcsfEvent]]) -> str:
        """Query Kuzu for bounded graph context. LIMIT 20 per entity."""
        conn = kuzu.Connection(self._kuzu_db)
        lines = []
        seen_users = set()
        seen_procs = set()
        limit = self._settings.graph_context_limit

        for _, event in events:
            if isinstance(event, ProcessActivity) and event.actor:
                user = event.actor.user.name
                if user and user not in seen_users:
                    seen_users.add(user)
                    try:
                        result = conn.execute(
                            "MATCH (u:User {id: $user})-[r:SPAWNED]->(p:Process) "
                            "RETURN p.name, r.timestamp "
                            "ORDER BY r.timestamp DESC LIMIT $limit",
                            {"user": user, "limit": limit},
                        )
                        entries = []
                        while result.has_next():
                            row = result.get_next()
                            entries.append(f"  {row[0]} at {row[1]}")
                        if entries:
                            lines.append(f"User '{user}' recent processes:")
                            lines.extend(entries)
                    except Exception:
                        pass

            if isinstance(event, NetworkActivity) and event.process:
                proc_name = event.process.name
                if proc_name and proc_name not in seen_procs:
                    seen_procs.add(proc_name)
                    try:
                        result = conn.execute(
                            "MATCH (p:Process {name: $proc})-[c:CONNECTED_TO]->(ip:IP) "
                            "RETURN ip.address, c.dst_port, c.timestamp "
                            "ORDER BY c.timestamp DESC LIMIT $limit",
                            {"proc": proc_name, "limit": limit},
                        )
                        entries = []
                        while result.has_next():
                            row = result.get_next()
                            entries.append(f"  {row[0]}:{row[1]} at {row[2]}")
                        if entries:
                            lines.append(f"Process '{proc_name}' recent connections:")
                            lines.extend(entries)
                    except Exception:
                        pass

        return "\n".join(lines)

    def _parse_findings(
        self, content: str, events: list[tuple[int, OcsfEvent]]
    ) -> list[SecurityFinding]:
        """Parse LLM response into SecurityFinding objects."""
        # Extract JSON from the response
        content = content.strip()
        if content.startswith("```"):
            # Strip markdown code fences
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            raw_findings = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON")
            return []

        if not isinstance(raw_findings, list):
            return []

        # Build PID lookup from events: entity_name -> pid
        pid_lookup: dict[str, int] = {}
        for _, event in events:
            if isinstance(event, ProcessActivity) or (
                isinstance(event, (NetworkActivity, DnsActivity, FileActivity, RegistryActivity)) and event.process
            ):
                pid_lookup[event.process.name] = event.process.pid

        batch_pids = self._collect_batch_pids(events)

        findings = []
        for raw in raw_findings:
            try:
                # Check if this is an update to an existing finding
                finding_id = raw.get("id")
                if finding_id and self._queue and self._is_existing_finding(finding_id):
                    self._queue.update_finding(
                        finding_id,
                        new_evidence_ids=raw.get("evidence_event_ids"),
                        new_description=raw.get("description"),
                        new_severity=raw.get("severity"),
                    )
                    logger.info("Updated existing finding %s", finding_id)
                    continue

                chain_data = raw.get("chain", [])
                chain = []
                finding_pids: set[int] = set()
                for step in chain_data:
                    step_pid = step.get("pid")
                    # Try to match entity_name to a PID from events
                    if step_pid is None and step.get("entity_type") == "process":
                        step_pid = pid_lookup.get(step.get("entity_name"))
                    if step_pid is not None:
                        finding_pids.add(step_pid)
                    chain.append(
                        ChainStep(
                            entity_type=step.get("entity_type", "unknown"),
                            entity_id=step.get("entity_id", ""),
                            entity_name=step.get("entity_name", ""),
                            pid=step_pid,
                        )
                    )

                # If no chain provided, build one from affected entities
                if not chain:
                    chain = self._build_chain_from_events(events)
                    for step in chain:
                        if step.pid is not None:
                            finding_pids.add(step.pid)

                # Build affected_pids: prefer LLM-provided, then chain-extracted,
                # then all PIDs from the batch.  Filter to real ints > 0.
                affected_pids = [
                    int(p) for p in (raw.get("affected_pids") or [])
                    if isinstance(p, (int, float)) and int(p) > 0
                ]
                if not affected_pids:
                    affected_pids = sorted(p for p in finding_pids if p > 0)
                if not affected_pids:
                    affected_pids = batch_pids

                # Extract IOCs from LLM output
                raw_iocs = raw.get("iocs") or {}
                iocs = {}
                for key in ("domains", "ips", "files", "urls"):
                    vals = raw_iocs.get(key)
                    if vals and isinstance(vals, list):
                        iocs[key] = [str(v) for v in vals if v]

                finding = SecurityFinding(
                    id=str(uuid.uuid4()),
                    timestamp=datetime.now(),
                    severity=raw.get("severity", "info"),
                    title=raw.get("title", "Unknown finding"),
                    description=raw.get("description", ""),
                    affected_entities=raw.get("affected_entities", []),
                    evidence_event_ids=raw.get("evidence_event_ids", []),
                    recommendation=raw.get("recommendation", ""),
                    chain=chain,
                    affected_pids=affected_pids,
                    iocs=iocs,
                )
                findings.append(finding)
            except Exception:
                logger.debug("Failed to parse individual finding", exc_info=True)

        return findings

    def _is_existing_finding(self, finding_id: str) -> bool:
        """Check if a finding ID exists in the queue."""
        if not self._queue:
            return False
        try:
            conn = self._queue._get_conn()
            row = conn.execute(
                "SELECT id FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return row is not None
        except Exception:
            return False

    def _build_chain_from_events(
        self, events: list[tuple[int, OcsfEvent]]
    ) -> list[ChainStep]:
        """Build a chain from the events if the LLM didn't provide one."""
        chain = []
        for _, event in events[:3]:  # Use first 3 events max
            if isinstance(event, ProcessActivity):
                if event.actor:
                    chain.append(
                        ChainStep(
                            entity_type="user",
                            entity_id=event.actor.user.name,
                            entity_name=event.actor.user.name,
                            timestamp=event.time,
                        )
                    )
                chain.append(
                    ChainStep(
                        entity_type="process",
                        entity_id=f"{event.device.hostname}:{event.process.pid}",
                        entity_name=event.process.name,
                        pid=event.process.pid,
                        timestamp=event.time,
                    )
                )
            elif isinstance(event, NetworkActivity):
                if event.process:
                    chain.append(
                        ChainStep(
                            entity_type="process",
                            entity_id=event.process.name,
                            entity_name=event.process.name,
                            pid=event.process.pid,
                            timestamp=event.time,
                        )
                    )
                if event.dst_endpoint:
                    chain.append(
                        ChainStep(
                            entity_type="ip",
                            entity_id=event.dst_endpoint.ip,
                            entity_name=event.dst_endpoint.ip,
                            timestamp=event.time,
                        )
                    )
            elif isinstance(event, (DnsActivity, FileActivity, RegistryActivity)):
                if event.process:
                    chain.append(
                        ChainStep(
                            entity_type="process",
                            entity_id=event.process.name,
                            entity_name=event.process.name,
                            pid=event.process.pid,
                            timestamp=event.time,
                        )
                    )
        return chain

    @staticmethod
    def _collect_batch_pids(events: list[tuple[int, OcsfEvent]]) -> list[int]:
        """Collect all unique PIDs > 0 from a batch of events.

        PID 0 is filtered out — it comes from mDNSResponder (DNS) and FSEvents
        (file activity) where the originating process is unknown.
        """
        pids = set()
        for _, event in events:
            if isinstance(event, ProcessActivity):
                if event.process.pid > 0:
                    pids.add(event.process.pid)
            elif isinstance(event, (NetworkActivity, DnsActivity, FileActivity, RegistryActivity)) and event.process and event.process.pid > 0:
                pids.add(event.process.pid)
        return list(pids)
