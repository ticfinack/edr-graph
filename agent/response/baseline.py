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
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def _match_chain_pattern(chain_names: list[str], pattern_parts: list[str]) -> bool:
    """Match a list of process names against a chain pattern.

    Pattern parts are separated by '>' (already split and stripped).
    Named steps match via fnmatch (case-insensitive).
    '*' matches exactly one process in the chain.
    '**' matches zero or more processes in the chain.

    The pattern is anchored at the END of the chain (must consume through the
    last chain element) but un-anchored at the start — it can begin matching
    at any position.  E.g. ``bash > caffeinate`` matches the tail of
    ``launchd > Terminal > … > bash > caffeinate``.
    """
    for start in range(len(chain_names)):
        if _match_chain_recursive(chain_names, start, pattern_parts, 0):
            return True
    # Edge case: empty chain can match an all-** pattern
    if not chain_names:
        return _match_chain_recursive(chain_names, 0, pattern_parts, 0)
    return False


def _match_chain_recursive(
    chain: list[str], ci: int, pattern: list[str], pi: int
) -> bool:
    # Base case: pattern exhausted
    if pi == len(pattern):
        return ci == len(chain)

    part = pattern[pi]

    if part == "**":
        # '**' matches zero or more chain steps
        # Try consuming 0, 1, 2, ... chain steps
        return any(_match_chain_recursive(chain, skip, pattern, pi + 1) for skip in range(ci, len(chain) + 1))

    # Need at least one chain element to match
    if ci >= len(chain):
        return False

    if part == "*":
        # '*' matches exactly one chain step
        return _match_chain_recursive(chain, ci + 1, pattern, pi + 1)

    # Named step: match via fnmatch (case-insensitive)
    if fnmatch.fnmatch(chain[ci].lower(), part.lower()):
        return _match_chain_recursive(chain, ci + 1, pattern, pi + 1)

    return False


def _extract_chain_names(chain: list) -> list[str]:
    """Extract process names from a chain (list of objects or dicts)."""
    if not chain:
        return []
    if hasattr(chain[0], "entity_type"):
        return [s.entity_name for s in chain if s.entity_type == "process"]
    return [
        s["entity_name"]
        for s in chain
        if s.get("entity_type") == "process"
    ]


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
        chain_names = _extract_chain_names(chain)
        filter_parts = [p.strip() for p in chain_filter.split(">")]
        if not _match_chain_pattern(chain_names, filter_parts):
            return False

    if rt == "chain_pattern" and chain is not None:
        chain_names = _extract_chain_names(chain)
        pattern_parts = [p.strip() for p in pat.split(">")]
        return _match_chain_pattern(chain_names, pattern_parts)

    if rt == "process_name" and process_name:
        return fnmatch.fnmatch(process_name.lower(), pat.lower())

    if rt == "dst_ip" and dst_ip:
        return dst_ip == pat

    if rt == "dst_cidr" and dst_ip:
        try:
            return ipaddress.ip_address(dst_ip) in ipaddress.ip_network(
                pat, strict=False
            )
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
                "SELECT 1 FROM behavior_baseline "
                "WHERE process_name = ? AND behavior_type = ? AND target = ?",
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
                "SELECT behavior_type, COUNT(*) as cnt "
                "FROM behavior_baseline GROUP BY behavior_type"
            ).fetchall()
            by_type = {r["behavior_type"]: r["cnt"] for r in rows}

            total = conn.execute("SELECT COUNT(*) FROM behavior_baseline").fetchone()[0]

            range_row = conn.execute(
                "SELECT MIN(first_seen) as earliest, MAX(last_seen) as latest "
                "FROM behavior_baseline"
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

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        if not self._migrated:
            try:
                conn.execute("ALTER TABLE response_allowlist ADD COLUMN chain_filter TEXT NOT NULL DEFAULT ''")
                conn.commit()
            except Exception:
                pass  # Column already exists
            self._migrated = True
        return conn

    MAX_PATTERN_LENGTH = 500

    def add_rule(self, rule_type: str, pattern: str, description: str = "", chain_filter: str = "") -> int:
        """Add an allowlist rule. Returns rule ID.

        rule_type: "process_name", "dst_ip", "dst_cidr", "domain", "file_path", "finding_title"
        pattern: glob for process/file/title, CIDR for dst_cidr, exact for domain/dst_ip
        chain_filter: optional chain pattern that must also match for the rule to apply
        """
        if rule_type not in self.VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        if len(pattern) > self.MAX_PATTERN_LENGTH:
            raise ValueError(f"Pattern too long (max {self.MAX_PATTERN_LENGTH} chars)")
        if chain_filter and len(chain_filter) > self.MAX_PATTERN_LENGTH:
            raise ValueError(f"Chain filter too long (max {self.MAX_PATTERN_LENGTH} chars)")
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO response_allowlist (rule_type, pattern, description, chain_filter) "
                "VALUES (?, ?, ?, ?)",
                (rule_type, pattern, description, chain_filter),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID. Returns True if a rule was deleted."""
        conn = self._conn()
        try:
            cur = conn.execute(
                "DELETE FROM response_allowlist WHERE id = ?", (rule_id,)
            )
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
            rules = conn.execute(
                "SELECT * FROM response_allowlist ORDER BY id"
            ).fetchall()
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

        return False, ""

    def get_rules(self) -> list[dict]:
        """Return all rules for dashboard display."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM response_allowlist ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_graph_filterable_rules(self) -> list[dict]:
        """Return rules whose type can be applied at the graph-insertion stage.

        Excludes rules with a chain_filter (chain context is unavailable
        pre-LLM) and rule types that only make sense in the response engine
        (finding_title, chain_pattern).
        """
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM response_allowlist ORDER BY id"
            ).fetchall()
            return [
                dict(r)
                for r in rows
                if r["rule_type"] in self.GRAPH_FILTERABLE_TYPES
                and not r["chain_filter"]
            ]
        finally:
            conn.close()


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

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        if not self._migrated:
            try:
                conn.execute("ALTER TABLE response_blocklist ADD COLUMN chain_filter TEXT NOT NULL DEFAULT ''")
                conn.commit()
            except Exception:
                pass  # Column already exists
            self._migrated = True
        return conn

    def add_rule(self, rule_type: str, pattern: str, description: str = "", chain_filter: str = "") -> int:
        """Add a blocklist rule. Returns rule ID."""
        if rule_type not in self.VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO response_blocklist (rule_type, pattern, description, chain_filter) "
                "VALUES (?, ?, ?, ?)",
                (rule_type, pattern, description, chain_filter),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID. Returns True if a rule was deleted."""
        conn = self._conn()
        try:
            cur = conn.execute(
                "DELETE FROM response_blocklist WHERE id = ?", (rule_id,)
            )
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
            rules = conn.execute(
                "SELECT * FROM response_blocklist ORDER BY id"
            ).fetchall()
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

        return False, ""

    def get_rules(self) -> list[dict]:
        """Return all rules for dashboard display."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM response_blocklist ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
