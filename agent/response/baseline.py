"""Behavior baseline and response allowlist backed by SQLite.

BehaviorBaseline records observed process→network/file behaviors during
learning mode. ResponseAllowlist holds user-defined rules that exempt
known-good behaviors from response actions.

Both classes are thread-safe: they open per-operation connections.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)


class ChainEntry(NamedTuple):
    """A single element in a chain for pattern matching.

    Carries process name, command line, and container ID so that rules
    can match against any combination.
    """

    name: str
    cmd_line: str = ""
    container_id: str = ""


def _match_chain_pattern(chain: list[str | ChainEntry], pattern_parts: list[str]) -> bool:
    """Match a chain against a pattern.

    Pattern parts are separated by '>' (already split and stripped).

    Matching modes per pattern part:
      - ``name`` or ``name*``   — fnmatch against process name (default)
      - ``re:pattern``          — regex search against process name
      - ``cmd:glob``            — fnmatch against cmd_line
      - ``cmd_re:pattern``      — regex search against cmd_line
      - ``ctr:pattern``         — fnmatch against container_id
      - ``*``                   — matches exactly one chain step
      - ``**``                  — matches zero or more chain steps

    The pattern is anchored at the END of the chain but un-anchored at the
    start — it can begin matching at any position.
    """
    for start in range(len(chain)):
        if _match_chain_recursive(chain, start, pattern_parts, 0):
            return True
    # Edge case: empty chain can match an all-** pattern
    if not chain:
        return _match_chain_recursive(chain, 0, pattern_parts, 0)
    return False


def _entry_name(entry: str | ChainEntry) -> str:
    """Extract the display name from a chain entry."""
    return entry.name if isinstance(entry, ChainEntry) else entry


def _entry_cmdline(entry: str | ChainEntry) -> str:
    """Extract cmd_line from a chain entry (empty string for plain strings)."""
    return entry.cmd_line if isinstance(entry, ChainEntry) else ""


def _entry_container(entry: str | ChainEntry) -> str:
    """Extract container_id from a chain entry."""
    return entry.container_id if isinstance(entry, ChainEntry) else ""


# Cache compiled regex patterns to avoid recompilation on every match.
_regex_cache: dict[str, re.Pattern] = {}


def _get_regex(pattern: str) -> re.Pattern:
    compiled = _regex_cache.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern, re.IGNORECASE)
        _regex_cache[pattern] = compiled
    return compiled


def _match_step(entry: str | ChainEntry, part: str) -> bool:
    """Match a single chain entry against a single pattern part.

    Compound patterns joined with ``+`` require ALL sub-parts to match the
    same entry, e.g. ``ctr:abc*+cmd:/bin/bash*`` matches a process that is
    both in container abc… AND has cmd_line starting with /bin/bash.
    """
    if "+" in part:
        return all(_match_single(entry, sub) for sub in part.split("+"))
    return _match_single(entry, part)


def _match_single(entry: str | ChainEntry, part: str) -> bool:
    """Match a single qualifier against a chain entry."""
    if part.startswith("cmd_re:"):
        return bool(_get_regex(part[7:]).search(_entry_cmdline(entry)))
    if part.startswith("cmd:"):
        return fnmatch.fnmatch(_entry_cmdline(entry).lower(), part[4:].lower())
    if part.startswith("ctr:"):
        return fnmatch.fnmatch(_entry_container(entry).lower(), part[4:].lower())
    if part.startswith("re:"):
        return bool(_get_regex(part[3:]).search(_entry_name(entry)))
    # Default: fnmatch against name (case-insensitive)
    return fnmatch.fnmatch(_entry_name(entry).lower(), part.lower())


def _match_chain_recursive(
    chain: list[str | ChainEntry], ci: int, pattern: list[str], pi: int,
) -> bool:
    # Base case: pattern exhausted
    if pi == len(pattern):
        return ci == len(chain)

    part = pattern[pi]

    if part == "**":
        # '**' matches zero or more chain steps
        return any(
            _match_chain_recursive(chain, skip, pattern, pi + 1)
            for skip in range(ci, len(chain) + 1)
        )

    # Need at least one chain element to match
    if ci >= len(chain):
        return False

    if part == "*":
        # '*' matches exactly one chain step
        return _match_chain_recursive(chain, ci + 1, pattern, pi + 1)

    if _match_step(chain[ci], part):
        return _match_chain_recursive(chain, ci + 1, pattern, pi + 1)

    return False


def _extract_chain_entries(chain: list) -> list[ChainEntry]:
    """Extract chain entries from a chain (list of ChainStep objects or dicts).

    User entries have names prefixed with ``USER:`` so that rules can target
    specific users without colliding with identically-named processes.
    Process entries carry cmd_line and container_id when available.
    """
    if not chain:
        return []
    entries: list[ChainEntry] = []
    if hasattr(chain[0], "entity_type"):
        for s in chain:
            if s.entity_type == "user":
                entries.append(ChainEntry(name=f"USER:{s.entity_name}"))
            elif s.entity_type == "process":
                entries.append(ChainEntry(
                    name=s.entity_name,
                    cmd_line=getattr(s, "cmd_line", "") or "",
                    container_id=getattr(s, "container_id", "") or "",
                ))
    else:
        for s in chain:
            if s.get("entity_type") == "user":
                entries.append(ChainEntry(name="USER:" + s["entity_name"]))
            elif s.get("entity_type") == "process":
                entries.append(ChainEntry(
                    name=s["entity_name"],
                    cmd_line=s.get("cmd_line", ""),
                    container_id=s.get("container_id", ""),
                ))
    return entries


def _extract_chain_names(chain: list) -> list[str]:
    """Legacy wrapper: extract just names as plain strings."""
    return [e.name for e in _extract_chain_entries(chain)]


def _match_rule(
    rule: dict,
    process_name: str = "",
    dst_ip: str = "",
    domain: str = "",
    file_path: str = "",
    finding_title: str = "",
    chain: list | None = None,
) -> bool:
    """Shared matching logic for a single rule against the given attributes.

    If the rule has a non-empty ``chain_filter``, the chain must also match
    the filter pattern for the rule to apply.  This allows scoping IOC-based
    rules (domain, dst_ip, …) to a specific process ancestry.

    Returns True if the rule matches.
    """
    rt = rule["rule_type"]
    pat = rule["pattern"]

    # Check chain_filter first — if present, chain must match it
    chain_filter = rule.get("chain_filter", "")
    if chain_filter:
        if chain is None:
            return False
        chain_entries = _extract_chain_entries(chain)
        filter_parts = [p.strip() for p in chain_filter.split(">")]
        if not _match_chain_pattern(chain_entries, filter_parts):
            return False

    # Check chain_exclude — if present and chain matches, rule does NOT fire
    chain_exclude = rule.get("chain_exclude", "")
    if chain_exclude and chain is not None:
        chain_entries = _extract_chain_entries(chain)
        exclude_parts = [p.strip() for p in chain_exclude.split(">")]
        if _match_chain_pattern(chain_entries, exclude_parts):
            return False

    if rt == "chain_pattern" and chain is not None:
        chain_entries = _extract_chain_entries(chain)
        pattern_parts = [p.strip() for p in pat.split(">")]
        return _match_chain_pattern(chain_entries, pattern_parts)

    if rt == "process_name" and process_name:
        return fnmatch.fnmatch(process_name.lower(), pat.lower())

    if rt == "dst_ip" and dst_ip:
        return dst_ip == pat

    if rt == "dst_cidr" and dst_ip:
        try:
            return ipaddress.ip_address(dst_ip) in ipaddress.ip_network(pat, strict=False)
        except ValueError:
            return False

    if rt == "domain" and domain:
        return domain.lower() == pat.lower()

    if rt == "file_path" and file_path:
        return fnmatch.fnmatch(file_path, pat)

    if rt == "finding_title" and finding_title:
        return fnmatch.fnmatch(finding_title, pat)

    return False


class BehaviorBaseline:
    """Records observed process→network/file behaviors. Thread-safe."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = str(db_path)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def record(self, process_name: str, behavior_type: str, target: str) -> None:
        """Record an observed behavior (upserts: increments hit_count, updates last_seen)."""
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO behavior_baseline (process_name, behavior_type, target, "
                "first_seen, last_seen, hit_count) "
                "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%f','now'), "
                "strftime('%Y-%m-%dT%H:%M:%f','now'), 1) "
                "ON CONFLICT(process_name, behavior_type, target) DO UPDATE SET "
                "hit_count = hit_count + 1, "
                "last_seen = strftime('%Y-%m-%dT%H:%M:%f','now')",
                (process_name, behavior_type, target),
            )
            conn.commit()
        finally:
            conn.close()

    def is_baselined(self, process_name: str, behavior_type: str, target: str) -> bool:
        """Check if a behavior was observed during learning."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM behavior_baseline WHERE process_name = ? AND behavior_type = ? AND target = ?",
                (process_name, behavior_type, target),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def clear(self) -> None:
        """Wipe the baseline (for restart of learning)."""
        conn = self._conn()
        try:
            conn.execute("DELETE FROM behavior_baseline")
            conn.commit()
        finally:
            conn.close()

    def stats(self) -> dict:
        """Return counts by behavior_type, total entries, date range."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT behavior_type, COUNT(*) as cnt FROM behavior_baseline GROUP BY behavior_type"
            ).fetchall()
            by_type = {r["behavior_type"]: r["cnt"] for r in rows}

            total = conn.execute("SELECT COUNT(*) FROM behavior_baseline").fetchone()[0]

            range_row = conn.execute(
                "SELECT MIN(first_seen) as earliest, MAX(last_seen) as latest FROM behavior_baseline"
            ).fetchone()

            return {
                "total": total,
                "by_type": by_type,
                "earliest": range_row["earliest"] if range_row else None,
                "latest": range_row["latest"] if range_row else None,
            }
        finally:
            conn.close()

    def get_entries(self, limit: int = 100) -> list[dict]:
        """Return recent baseline entries for dashboard display."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM behavior_baseline ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_all_entries_raw(self) -> list[tuple[str, str, str]]:
        """Return all (process_name, behavior_type, target) tuples for caching."""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT process_name, behavior_type, target FROM behavior_baseline").fetchall()
            return [(r["process_name"], r["behavior_type"], r["target"]) for r in rows]
        finally:
            conn.close()


class BaselineGateCache:
    """Thread-safe cache of baseline entries for graph gating.

    Loads all baseline (process_name, behavior_type, target) tuples into a
    frozenset for O(1) lookup. Refreshes from SQLite at most every
    ``refresh_interval`` seconds.
    """

    def __init__(
        self,
        baseline: BehaviorBaseline,
        refresh_interval: float = 30.0,
    ) -> None:
        self._baseline = baseline
        self._refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._entries: frozenset[tuple[str, str, str]] = frozenset()
        self._last_refresh: float = 0.0
        self._invalidated = True  # force initial load

    def _refresh_if_stale(self) -> None:
        now = time.monotonic()
        if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
            with self._lock:
                # Double-check after acquiring lock
                if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
                    raw = self._baseline.get_all_entries_raw()
                    self._entries = frozenset(raw)
                    self._last_refresh = time.monotonic()
                    self._invalidated = False

    def is_gated(self, process_name: str, behavior_type: str, target: str) -> bool:
        """Return True if the (process_name, behavior_type, target) is baselined."""
        self._refresh_if_stale()
        return (process_name, behavior_type, target) in self._entries

    def has_entries(self) -> bool:
        """Return True if the cache has any baseline entries."""
        self._refresh_if_stale()
        return bool(self._entries)

    def invalidate(self) -> None:
        """Force a refresh on the next access."""
        self._invalidated = True


class ResponseAllowlist:
    """User-defined rules that exempt behaviors from response actions."""

    VALID_RULE_TYPES = {
        "process_name",
        "dst_ip",
        "dst_cidr",
        "domain",
        "file_path",
        "finding_title",
        "chain_pattern",
    }

    GRAPH_FILTERABLE_TYPES = {
        "process_name",
        "dst_ip",
        "dst_cidr",
        "domain",
        "file_path",
    }

    def __init__(self, db_path: Path) -> None:
        self._db_path = str(db_path)
        self._migrated = False
        self._network_rules: list[dict] = []

    def set_network_rules(self, rules: list[dict]) -> None:
        """Atomically replace network-distributed rules (from fleet server)."""
        self._network_rules = list(rules)

    def get_network_rules(self) -> list[dict]:
        """Return current network-distributed rules for introspection."""
        return list(self._network_rules)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        if not self._migrated:
            for col in ("chain_filter", "chain_exclude"):
                try:
                    conn.execute(f"ALTER TABLE response_allowlist ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
                    conn.commit()
                except Exception:
                    pass  # Column already exists
            self._migrated = True
        return conn

    MAX_PATTERN_LENGTH = 500

    def add_rule(
        self, rule_type: str, pattern: str, description: str = "",
        chain_filter: str = "", chain_exclude: str = "",
    ) -> int:
        """Add an allowlist rule. Returns rule ID.

        rule_type: "process_name", "dst_ip", "dst_cidr", "domain", "file_path",
                   "finding_title", "chain_pattern"
        pattern: glob for process/file/title, CIDR for dst_cidr, exact for domain/dst_ip
        chain_filter: optional chain pattern that must also match for the rule to apply
        chain_exclude: optional chain pattern — if matched, the rule does NOT apply
        """
        if rule_type not in self.VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        if len(pattern) > self.MAX_PATTERN_LENGTH:
            raise ValueError(f"Pattern too long (max {self.MAX_PATTERN_LENGTH} chars)")
        for field_name, field_val in [("chain_filter", chain_filter), ("chain_exclude", chain_exclude)]:
            if field_val and len(field_val) > self.MAX_PATTERN_LENGTH:
                raise ValueError(f"{field_name} too long (max {self.MAX_PATTERN_LENGTH} chars)")
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO response_allowlist (rule_type, pattern, description, chain_filter, chain_exclude)"
                " VALUES (?, ?, ?, ?, ?)",
                (rule_type, pattern, description, chain_filter, chain_exclude),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID. Returns True if a rule was deleted."""
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM response_allowlist WHERE id = ?", (rule_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def is_allowed(
        self,
        process_name: str = "",
        dst_ip: str = "",
        domain: str = "",
        file_path: str = "",
        finding_title: str = "",
        chain: list | None = None,
    ) -> tuple[bool, str]:
        """Check if any allowlist rule matches. Returns (matched, rule_description)."""
        conn = self._conn()
        try:
            rules = conn.execute("SELECT * FROM response_allowlist ORDER BY id").fetchall()
        finally:
            conn.close()

        for rule in rules:
            desc = rule["description"] or rule["pattern"]
            if _match_rule(
                dict(rule),
                process_name=process_name,
                dst_ip=dst_ip,
                domain=domain,
                file_path=file_path,
                finding_title=finding_title,
                chain=chain,
            ):
                return True, desc

        # Check network-distributed rules
        for rule in self._network_rules:
            desc = rule.get("description") or rule.get("pattern", "")
            if _match_rule(
                rule,
                process_name=process_name,
                dst_ip=dst_ip,
                domain=domain,
                file_path=file_path,
                finding_title=finding_title,
                chain=chain,
            ):
                return True, desc

        return False, ""

    def get_rules(self) -> list[dict]:
        """Return all rules for dashboard display."""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM response_allowlist ORDER BY id").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_graph_filterable_rules(self) -> list[dict]:
        """Return rules whose type can be applied at the graph-insertion stage.

        Excludes rules with a chain_filter (chain context is unavailable
        pre-LLM) and rule types that only make sense in the response engine
        (finding_title, chain_pattern).

        Includes matching network-distributed rules (defense in depth).
        """
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM response_allowlist ORDER BY id").fetchall()
            result = [dict(r) for r in rows if r["rule_type"] in self.GRAPH_FILTERABLE_TYPES and not r["chain_filter"]]
        finally:
            conn.close()
        # Extend with network rules that qualify for pre-graph filtering
        result.extend(
            r for r in self._network_rules
            if r.get("rule_type") in self.GRAPH_FILTERABLE_TYPES and not r.get("chain_filter")
        )
        return result


class AllowlistRuleCache:
    """Thread-safe cache of graph-filterable allowlist rules.

    Refreshes from SQLite at most every ``refresh_interval`` seconds to
    avoid hammering the database on every event batch.
    """

    def __init__(
        self,
        allowlist: ResponseAllowlist,
        refresh_interval: float = 5.0,
    ) -> None:
        self._allowlist = allowlist
        self._refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._rules: list[dict] = []
        self._last_refresh: float = 0.0
        self._invalidated = True  # force initial load

    def get_rules(self) -> list[dict]:
        """Return cached graph-filterable rules, refreshing if stale."""
        now = time.monotonic()
        if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
            with self._lock:
                # Double-check after acquiring lock
                if self._invalidated or (now - self._last_refresh >= self._refresh_interval):
                    self._rules = self._allowlist.get_graph_filterable_rules()
                    self._last_refresh = now
                    self._invalidated = False
        return self._rules

    def invalidate(self) -> None:
        """Force a refresh on the next ``get_rules()`` call."""
        self._invalidated = True


class ResponseBlocklist:
    """User-defined rules that force response actions even if baselined.

    Same structure as ResponseAllowlist but semantics are inverted:
    a matched rule means "always respond to this behavior".
    """

    VALID_RULE_TYPES = {
        "process_name",
        "dst_ip",
        "dst_cidr",
        "domain",
        "file_path",
        "finding_title",
        "chain_pattern",
    }

    def __init__(self, db_path: Path) -> None:
        self._db_path = str(db_path)
        self._migrated = False
        self._network_rules: list[dict] = []

    def set_network_rules(self, rules: list[dict]) -> None:
        """Atomically replace network-distributed rules (from fleet server)."""
        self._network_rules = list(rules)

    def get_network_rules(self) -> list[dict]:
        """Return current network-distributed rules for introspection."""
        return list(self._network_rules)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        if not self._migrated:
            for col in ("chain_filter", "chain_exclude"):
                try:
                    conn.execute(f"ALTER TABLE response_blocklist ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
                    conn.commit()
                except Exception:
                    pass  # Column already exists
            self._migrated = True
        return conn

    def add_rule(
        self, rule_type: str, pattern: str, description: str = "",
        chain_filter: str = "", chain_exclude: str = "",
    ) -> int:
        """Add a blocklist rule. Returns rule ID."""
        if rule_type not in self.VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO response_blocklist (rule_type, pattern, description, chain_filter, chain_exclude)"
                " VALUES (?, ?, ?, ?, ?)",
                (rule_type, pattern, description, chain_filter, chain_exclude),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID. Returns True if a rule was deleted."""
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM response_blocklist WHERE id = ?", (rule_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def is_blocked(
        self,
        process_name: str = "",
        dst_ip: str = "",
        domain: str = "",
        file_path: str = "",
        finding_title: str = "",
        chain: list | None = None,
    ) -> tuple[bool, str]:
        """Check if any blocklist rule matches. Returns (matched, rule_description)."""
        conn = self._conn()
        try:
            rules = conn.execute("SELECT * FROM response_blocklist ORDER BY id").fetchall()
        finally:
            conn.close()

        for rule in rules:
            desc = rule["description"] or rule["pattern"]
            if _match_rule(
                dict(rule),
                process_name=process_name,
                dst_ip=dst_ip,
                domain=domain,
                file_path=file_path,
                finding_title=finding_title,
                chain=chain,
            ):
                return True, desc

        # Check network-distributed rules
        for rule in self._network_rules:
            desc = rule.get("description") or rule.get("pattern", "")
            if _match_rule(
                rule,
                process_name=process_name,
                dst_ip=dst_ip,
                domain=domain,
                file_path=file_path,
                finding_title=finding_title,
                chain=chain,
            ):
                return True, desc

        return False, ""

    def get_rules(self) -> list[dict]:
        """Return all rules for dashboard display."""
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM response_blocklist ORDER BY id").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
