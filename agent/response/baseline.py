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
from pathlib import Path

logger = logging.getLogger(__name__)


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
    }

    def __init__(self, db_path: Path) -> None:
        self._db_path = str(db_path)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def add_rule(self, rule_type: str, pattern: str, description: str = "") -> int:
        """Add an allowlist rule. Returns rule ID.

        rule_type: "process_name", "dst_ip", "dst_cidr", "domain", "file_path", "finding_title"
        pattern: glob for process/file/title, CIDR for dst_cidr, exact for domain/dst_ip
        """
        if rule_type not in self.VALID_RULE_TYPES:
            raise ValueError(f"Invalid rule_type: {rule_type}")
        conn = self._conn()
        try:
            cur = conn.execute(
                "INSERT INTO response_allowlist (rule_type, pattern, description) "
                "VALUES (?, ?, ?)",
                (rule_type, pattern, description),
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
            rt = rule["rule_type"]
            pat = rule["pattern"]
            desc = rule["description"] or pat

            if rt == "process_name" and process_name:
                if fnmatch.fnmatch(process_name.lower(), pat.lower()):
                    return True, desc
            elif rt == "dst_ip" and dst_ip:
                if dst_ip == pat:
                    return True, desc
            elif rt == "dst_cidr" and dst_ip:
                try:
                    if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(
                        pat, strict=False
                    ):
                        return True, desc
                except ValueError:
                    pass
            elif rt == "domain" and domain:
                if domain.lower() == pat.lower():
                    return True, desc
            elif rt == "file_path" and file_path:
                if fnmatch.fnmatch(file_path, pat):
                    return True, desc
            elif rt == "finding_title" and finding_title:
                if fnmatch.fnmatch(finding_title, pat):
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
