"""Synchronous fast-path blocklist enforcer.

Evaluates blocklist rules in the processor hot loop immediately after entity
extraction, using O(1) in-memory structures.  Matched events trigger immediate
response actions without waiting for LLM analysis.

Pattern: follows ``AllowlistRuleCache`` in baseline.py — thread-safe, periodic
refresh from SQLite, ``invalidate()`` method.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import threading
import time
import uuid
from datetime import datetime

from agent.processor.entity_extractor import (
    ExtractedEntities,
    _name_cache,
    _ppid_cache,
    _username_cache,
)
from agent.response.baseline import ResponseBlocklist, _match_chain_pattern
from agent.schema.graph_types import ChainStep, SecurityFinding

logger = logging.getLogger(__name__)


def _build_chain_from_caches(pid: int, process_name: str) -> list[str]:
    """Walk ppid_cache to reconstruct chain names, prepend USER: if known."""
    seen: set[int] = set()
    current = pid
    ancestors: list[str] = []
    while current and current > 0 and current not in seen:
        seen.add(current)
        parent = _ppid_cache.get(current)
        if parent and parent > 0:
            name = _name_cache.get(parent, "")
            if name:
                ancestors.append(name)
        current = parent
    # Build chain: user (if known) + reversed ancestors + current process
    chain: list[str] = []
    username = _username_cache.get(pid, "")
    if username:
        chain.append(f"USER:{username}")
    chain.extend(reversed(ancestors))
    chain.append(process_name)
    return chain


class FastBlocklist:
    """Thread-safe, periodically-refreshed compiled blocklist for O(1) matching."""

    def __init__(self, blocklist: ResponseBlocklist, refresh_interval: float = 5.0) -> None:
        self._blocklist = blocklist
        self._refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._last_refresh: float = 0.0
        self._invalidated = True  # force initial load

        # Compiled structures
        self._ips: set[str] = set()
        self._domains: set[str] = set()
        self._cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._process_names: list[tuple[str, str]] = []  # (pattern, description)
        self._file_paths: list[tuple[str, str]] = []  # (pattern, description)
        self._chain_patterns: list[tuple[list[str], str]] = []  # (split_parts, description)
        self._has_rules: bool = False

    def _refresh_if_stale(self) -> None:
        now = time.monotonic()
        if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
            with self._lock:
                # Double-check after acquiring lock
                if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
                    self._compile_rules()
                    self._last_refresh = time.monotonic()
                    self._invalidated = False

    def _compile_rules(self) -> None:
        """Load rules from SQLite and compile into fast lookup structures."""
        try:
            rules = self._blocklist.get_rules()
        except Exception:
            logger.debug("Failed to load blocklist rules for fast-path", exc_info=True)
            return

        ips: set[str] = set()
        domains: set[str] = set()
        cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        process_names: list[tuple[str, str]] = []
        file_paths: list[tuple[str, str]] = []
        chain_patterns: list[tuple[list[str], str]] = []

        for rule in rules:
            rt = rule["rule_type"]
            pat = rule["pattern"]
            desc = rule.get("description") or pat

            if rt == "dst_ip":
                ips.add(pat)
            elif rt == "domain":
                domains.add(pat.lower())
            elif rt == "dst_cidr":
                try:
                    cidrs.append(ipaddress.ip_network(pat, strict=False))
                except ValueError:
                    logger.warning("Invalid CIDR in blocklist: %s", pat)
            elif rt == "process_name":
                process_names.append((pat, desc))
            elif rt == "file_path":
                file_paths.append((pat, desc))
            elif rt == "chain_pattern":
                parts = [p.strip() for p in pat.split(">")]
                chain_patterns.append((parts, desc))

        self._ips = ips
        self._domains = domains
        self._cidrs = cidrs
        self._process_names = process_names
        self._file_paths = file_paths
        self._chain_patterns = chain_patterns
        self._has_rules = bool(ips or domains or cidrs or process_names or file_paths or chain_patterns)

    def evaluate(
        self,
        entities: ExtractedEntities,
        ocsf,
        event_id: int,
    ) -> tuple[SecurityFinding, str] | None:
        """Evaluate entities against compiled blocklist rules.

        Returns ``(SecurityFinding, match_description)`` on hit, or ``None``.
        """
        self._refresh_if_stale()

        if not self._has_rules:
            return None

        # IP check
        for edge in entities.connected_edges:
            ip = edge.get("ip_id", "")
            if not ip:
                continue
            if ip in self._ips:
                return self._synthesize(entities, ocsf, event_id, f"Blocked IP: {ip}", "dst_ip", ip)
            # CIDR fallback
            try:
                addr = ipaddress.ip_address(ip)
                for net in self._cidrs:
                    if addr in net:
                        return self._synthesize(
                            entities, ocsf, event_id, f"Blocked CIDR {net}: {ip}", "dst_cidr", ip
                        )
            except ValueError:
                pass

        # Domain check
        for domain_node in entities.domains:
            name = domain_node.name.lower() if domain_node.name else ""
            if name and name in self._domains:
                return self._synthesize(
                    entities, ocsf, event_id, f"Blocked domain: {name}", "domain", name
                )

        # Process name check
        for proc in entities.processes:
            for pat, _desc in self._process_names:
                if fnmatch.fnmatch(proc.name.lower(), pat.lower()):
                    return self._synthesize(
                        entities, ocsf, event_id, f"Blocked process: {proc.name} (rule: {pat})",
                        "process_name", proc.name,
                    )

        # File path check
        for edge in entities.file_edges:
            file_id = edge.get("file_id", "")
            if not file_id:
                continue
            for pat, _desc in self._file_paths:
                if fnmatch.fnmatch(file_id, pat):
                    return self._synthesize(
                        entities, ocsf, event_id, f"Blocked file: {file_id} (rule: {pat})",
                        "file_path", file_id,
                    )

        # Chain pattern check
        if self._chain_patterns:
            for proc in entities.processes:
                chain_names = _build_chain_from_caches(proc.pid, proc.name)
                for parts, desc in self._chain_patterns:
                    if _match_chain_pattern(chain_names, parts):
                        chain_str = " > ".join(chain_names)
                        return self._synthesize(
                            entities, ocsf, event_id,
                            f"Blocked chain: {chain_str} (rule: {desc})",
                            "chain_pattern", chain_str,
                        )

        return None

    def _synthesize(
        self,
        entities: ExtractedEntities,
        ocsf,
        event_id: int,
        match_desc: str,
        rule_type: str,
        matched_value: str,
    ) -> tuple[SecurityFinding, str]:
        """Create a deterministic SecurityFinding for a fast-path blocklist hit."""
        # Build chain from entities
        chain: list[ChainStep] = []
        pids: list[int] = []
        process_name = ""

        for proc in entities.processes:
            chain.append(
                ChainStep(
                    entity_type="process",
                    entity_id=proc.id,
                    entity_name=proc.name,
                    pid=proc.pid if proc.pid > 0 else None,
                )
            )
            if proc.pid > 0:
                pids.append(proc.pid)
            if not process_name:
                process_name = proc.name

        # Add IP/domain entity to chain if relevant
        if rule_type in ("dst_ip", "dst_cidr"):
            chain.append(
                ChainStep(entity_type="ip", entity_id=matched_value, entity_name=matched_value)
            )
        elif rule_type == "domain":
            chain.append(
                ChainStep(entity_type="domain", entity_id=matched_value, entity_name=matched_value)
            )

        iocs: dict = {}
        if rule_type in ("dst_ip", "dst_cidr"):
            iocs["ips"] = [matched_value]
        elif rule_type == "domain":
            iocs["domains"] = [matched_value]
        elif rule_type == "file_path":
            iocs["files"] = [matched_value]

        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            severity="critical",
            title=f"Blocklist Hit ({rule_type}): {matched_value}",
            description=(
                f"Fast-path blocklist enforcer matched event {event_id}: {match_desc}. "
                f"This event was blocked synchronously in the processor pipeline "
                f"without waiting for LLM analysis."
            ),
            affected_entities=[matched_value],
            evidence_event_ids=[event_id],
            recommendation=(
                "Investigate the blocked activity. The blocklist rule triggered "
                "an immediate response action. Review audit trail for details."
            ),
            chain=chain,
            affected_pids=pids,
            iocs=iocs,
        )
        return finding, match_desc

    def invalidate(self) -> None:
        """Force a refresh on the next ``evaluate()`` call."""
        self._invalidated = True
