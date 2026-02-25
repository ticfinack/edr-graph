"""SQLite-backed settings database for users, registration keys, and config.

Thread-safe via threading.local() (same pattern as agent/queue/sqlite_queue.py).
WAL mode, busy_timeout=5000.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("server.settings_db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_keys (
    key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    expires_at INTEGER,
    max_uses INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER,
    revoked_by TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_key_map (
    agent_id TEXT PRIMARY KEY,
    registration_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    tag_name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '#3b82f6',
    priority INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_tags (
    agent_id TEXT NOT NULL,
    tag_name TEXT NOT NULL,
    assigned_at INTEGER NOT NULL,
    assigned_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, tag_name),
    FOREIGN KEY (tag_name) REFERENCES tags(tag_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tag_policies (
    tag_name TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    setting_value TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tag_name, setting_key),
    FOREIGN KEY (tag_name) REFERENCES tags(tag_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tag_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag_name TEXT NOT NULL,
    action TEXT NOT NULL,
    stage TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    chain_filter TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (tag_name) REFERENCES tags(tag_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS xdr_queries (
    query_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    query_type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT,
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS incident_surveillance_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    side TEXT NOT NULL,
    original_log_id INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    event_type TEXT NOT NULL,
    process_name TEXT,
    pid INTEGER,
    username TEXT,
    cmd_line TEXT,
    remote_ip TEXT,
    remote_port INTEGER,
    details_json TEXT,
    ingested_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_surv_dedup
    ON incident_surveillance_logs (incident_id, agent_id, original_log_id);

CREATE INDEX IF NOT EXISTS idx_surv_incident
    ON incident_surveillance_logs (incident_id, side);

CREATE TABLE IF NOT EXISTS surveillance_pull_state (
    incident_id TEXT NOT NULL,
    side TEXT NOT NULL,
    last_enqueue_at INTEGER NOT NULL DEFAULT 0,
    last_record_ts REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (incident_id, side)
);
"""

_DEFAULT_SETTINGS: dict[str, str] = {
    # Server settings
    "jwt_ttl_hours": "8",
    "lateral_movement_time_window": "300",
    "ntp_server": "pool.ntp.org",
    "ntp_sync_interval": "300",
    # Agent defaults (prefix agent_default_)
    "agent_default_response_mode": "learning",
    "agent_default_analyzer_interval": "60.0",
    "agent_default_collector_poll_interval": "1.0",
    "agent_default_novel_edge_threshold": "5",
    "agent_default_dga_score_threshold": "0.6",
    "agent_default_graph_ttl_hours": "24",
    "agent_default_auto_respond": "false",
    "agent_default_auto_terminate": "false",
    "agent_default_fleet_forward_events": "false",
    "agent_default_ioc_feeds_enabled": "true",
}

_VALID_AGENT_SETTINGS = {
    "response_mode",
    "analyzer_interval",
    "collector_poll_interval",
    "novel_edge_threshold",
    "dga_score_threshold",
    "graph_ttl_hours",
    "auto_respond",
    "auto_terminate",
    "fleet_forward_events",
    "ioc_feeds_enabled",
}

_VALID_RULE_ACTIONS = {"allow", "block"}
_VALID_RULE_STAGES = {"pre_graph", "fast_path", "response"}
_VALID_RULE_TYPES = {"process_name", "dst_ip", "dst_cidr", "domain", "file_path", "finding_title", "chain_pattern"}

_TAG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,49}$")
_TAG_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


class SettingsDB:
    """Thread-safe SQLite settings database."""

    def __init__(self, db_path: str | Path, global_rules_path: str | Path | None = None) -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        conn = self._conn()
        for statement in _SCHEMA.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(stmt)
        conn.commit()
        self._seed_defaults()
        self._global_rules: list[dict] = self._load_global_rules(global_rules_path)
        logger.info("SettingsDB initialized at %s (%d global rules)", self._db_path, len(self._global_rules))

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _seed_defaults(self) -> None:
        conn = self._conn()
        now = int(time.time())
        for key, value in _DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, now),
            )
        conn.commit()

    @staticmethod
    def _load_global_rules(path: str | Path | None) -> list[dict]:
        """Load global blocklist rules from a YAML file (graceful fallback)."""
        if path is None:
            return []
        path = Path(path)
        if not path.exists():
            return []
        try:
            import yaml

            with open(path) as fh:
                doc = yaml.safe_load(fh) or {}
            rules = []
            for r in doc.get("rules", []):
                rules.append({
                    "action": "block",
                    "stage": "fast_path",
                    "rule_type": r.get("rule_type", ""),
                    "pattern": r.get("pattern", ""),
                    "chain_filter": r.get("chain_filter", ""),
                    "description": r.get("description", ""),
                })
            return rules
        except Exception:
            logger.warning("Failed to load global rules from %s", path, exc_info=True)
            return []

    # ── Users ──

    def count_users(self) -> int:
        row = self._conn().execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
        return row["cnt"]

    def create_user(self, username: str, password_hash: str, role: str = "admin") -> dict:
        conn = self._conn()
        now = int(time.time())
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, now),
        )
        conn.commit()
        return {"username": username, "role": role, "created_at": now}

    def get_user(self, username: str) -> dict | None:
        row = self._conn().execute(
            "SELECT username, password_hash, role, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT username, role, created_at FROM users ORDER BY created_at ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def update_user(self, username: str, password_hash: str | None = None, role: str | None = None) -> bool:
        conn = self._conn()
        row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return False
        if password_hash is not None:
            conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
        if role is not None:
            conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.commit()
        return True

    def delete_user(self, username: str) -> bool:
        conn = self._conn()
        cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return cursor.rowcount > 0

    # ── Registration Keys ──

    def create_registration_key(
        self,
        key: str,
        label: str,
        created_by: str,
        expires_at: int | None = None,
        max_uses: int | None = None,
    ) -> dict:
        conn = self._conn()
        now = int(time.time())
        conn.execute(
            "INSERT INTO registration_keys (key, label, created_at, created_by, expires_at, max_uses) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (key, label, now, created_by, expires_at, max_uses),
        )
        conn.commit()
        return {
            "key": key,
            "label": label,
            "created_at": now,
            "created_by": created_by,
            "expires_at": expires_at,
            "max_uses": max_uses,
            "use_count": 0,
            "revoked": False,
        }

    def list_registration_keys(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM registration_keys ORDER BY created_at DESC"
        ).fetchall()
        now = int(time.time())
        keys = []
        for row in rows:
            d = dict(row)
            d["revoked"] = bool(d["revoked"])
            if d["revoked"]:
                d["status"] = "revoked"
            elif d["expires_at"] and d["expires_at"] < now:
                d["status"] = "expired"
            elif d["max_uses"] and d["use_count"] >= d["max_uses"]:
                d["status"] = "exhausted"
            else:
                d["status"] = "active"
            keys.append(d)
        return keys

    def validate_registration_key(self, key: str) -> tuple[bool, str]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM registration_keys WHERE key = ?", (key,)).fetchone()
        if not row:
            return False, "invalid_key"
        if row["revoked"]:
            return False, "key_revoked"
        now = int(time.time())
        if row["expires_at"] is not None and row["expires_at"] < now:
            return False, "key_expired"
        # Atomic increment with max_uses guard to prevent TOCTOU race
        if row["max_uses"] is not None:
            cur = conn.execute(
                "UPDATE registration_keys SET use_count = use_count + 1 "
                "WHERE key = ? AND use_count < ?",
                (key, row["max_uses"]),
            )
            conn.commit()
            if cur.rowcount == 0:
                return False, "max_uses_exceeded"
        else:
            conn.execute(
                "UPDATE registration_keys SET use_count = use_count + 1 WHERE key = ?",
                (key,),
            )
            conn.commit()
        return True, "ok"

    def revoke_registration_key(self, key: str, revoked_by: str) -> bool:
        conn = self._conn()
        now = int(time.time())
        cursor = conn.execute(
            "UPDATE registration_keys SET revoked = 1, revoked_at = ?, revoked_by = ? WHERE key = ?",
            (now, revoked_by, key),
        )
        conn.commit()
        return cursor.rowcount > 0

    def delete_registration_key(self, key: str) -> bool:
        conn = self._conn()
        cursor = conn.execute("DELETE FROM registration_keys WHERE key = ?", (key,))
        conn.commit()
        return cursor.rowcount > 0

    # ── Settings ──

    def get_setting(self, key: str) -> str | None:
        row = self._conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        conn = self._conn()
        now = int(time.time())
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, value, now),
        )
        conn.commit()

    def get_all_settings(self) -> dict[str, str]:
        rows = self._conn().execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def get_agent_defaults(self) -> dict[str, str]:
        all_settings = self.get_all_settings()
        prefix = "agent_default_"
        return {k[len(prefix):]: v for k, v in all_settings.items() if k.startswith(prefix)}

    def set_agent_default(self, key: str, value: str) -> None:
        self.set_setting(f"agent_default_{key}", value)

    def is_empty(self) -> bool:
        row = self._conn().execute("SELECT COUNT(*) AS cnt FROM users").fetchone()
        return row["cnt"] == 0

    # ── Agent-Key Mapping (for config signing) ──

    def set_agent_key(self, agent_id: str, registration_key: str) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO agent_key_map (agent_id, registration_key) VALUES (?, ?)",
            (agent_id, registration_key),
        )
        conn.commit()

    def get_agent_key(self, agent_id: str) -> str | None:
        row = self._conn().execute(
            "SELECT registration_key FROM agent_key_map WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        return row["registration_key"] if row else None

    # ── Tags CRUD ──

    def create_tag(self, tag_name: str, description: str = "", color: str = "#3b82f6", priority: int = 0) -> dict:
        if not _TAG_NAME_RE.match(tag_name):
            raise ValueError(f"Invalid tag name: {tag_name!r}")
        if not _TAG_COLOR_RE.match(color):
            raise ValueError(f"Invalid color: {color!r}. Must be a hex color like #3b82f6")
        conn = self._conn()
        now = int(time.time())
        conn.execute(
            "INSERT INTO tags (tag_name, description, color, priority, created_at) VALUES (?, ?, ?, ?, ?)",
            (tag_name, description, color, priority, now),
        )
        conn.commit()
        return {"tag_name": tag_name, "description": description, "color": color, "priority": priority, "created_at": now}

    def list_tags(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT t.tag_name, t.description, t.color, t.priority, t.created_at, "
            "COUNT(at.agent_id) AS agent_count "
            "FROM tags t LEFT JOIN agent_tags at ON t.tag_name = at.tag_name "
            "GROUP BY t.tag_name ORDER BY t.priority ASC, t.tag_name ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_tag(self, tag_name: str) -> dict | None:
        row = self._conn().execute(
            "SELECT tag_name, description, color, priority, created_at FROM tags WHERE tag_name = ?",
            (tag_name,),
        ).fetchone()
        return dict(row) if row else None

    def update_tag(self, tag_name: str, description: str | None = None, color: str | None = None, priority: int | None = None) -> bool:
        conn = self._conn()
        row = conn.execute("SELECT 1 FROM tags WHERE tag_name = ?", (tag_name,)).fetchone()
        if not row:
            return False
        if description is not None:
            conn.execute("UPDATE tags SET description = ? WHERE tag_name = ?", (description, tag_name))
        if color is not None:
            if not _TAG_COLOR_RE.match(color):
                raise ValueError(f"Invalid color: {color!r}. Must be a hex color like #3b82f6")
            conn.execute("UPDATE tags SET color = ? WHERE tag_name = ?", (color, tag_name))
        if priority is not None:
            conn.execute("UPDATE tags SET priority = ? WHERE tag_name = ?", (priority, tag_name))
        conn.commit()
        return True

    def delete_tag(self, tag_name: str) -> bool:
        conn = self._conn()
        cursor = conn.execute("DELETE FROM tags WHERE tag_name = ?", (tag_name,))
        conn.commit()
        return cursor.rowcount > 0

    # ── Agent-Tag Assignments ──

    def assign_tag(self, agent_id: str, tag_name: str, assigned_by: str = "") -> bool:
        conn = self._conn()
        tag = conn.execute("SELECT 1 FROM tags WHERE tag_name = ?", (tag_name,)).fetchone()
        if not tag:
            raise ValueError(f"Tag does not exist: {tag_name!r}")
        now = int(time.time())
        conn.execute(
            "INSERT OR IGNORE INTO agent_tags (agent_id, tag_name, assigned_at, assigned_by) VALUES (?, ?, ?, ?)",
            (agent_id, tag_name, now, assigned_by),
        )
        conn.commit()
        return True

    def remove_tag(self, agent_id: str, tag_name: str) -> bool:
        conn = self._conn()
        cursor = conn.execute(
            "DELETE FROM agent_tags WHERE agent_id = ? AND tag_name = ?",
            (agent_id, tag_name),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_agent_tags(self, agent_id: str) -> list[dict]:
        rows = self._conn().execute(
            "SELECT at.tag_name, at.assigned_at, at.assigned_by, t.color, t.priority "
            "FROM agent_tags at JOIN tags t ON at.tag_name = t.tag_name "
            "WHERE at.agent_id = ? ORDER BY t.priority ASC, at.tag_name ASC",
            (agent_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_tag_agents(self, tag_name: str) -> list[str]:
        rows = self._conn().execute(
            "SELECT agent_id FROM agent_tags WHERE tag_name = ? ORDER BY agent_id",
            (tag_name,),
        ).fetchall()
        return [r["agent_id"] for r in rows]

    def get_bulk_agent_tags(self, agent_ids: list[str]) -> dict[str, list[dict]]:
        if not agent_ids:
            return {}
        conn = self._conn()
        placeholders = ",".join("?" for _ in agent_ids)
        rows = conn.execute(
            f"SELECT at.agent_id, at.tag_name, t.color, t.priority "
            f"FROM agent_tags at JOIN tags t ON at.tag_name = t.tag_name "
            f"WHERE at.agent_id IN ({placeholders}) "
            f"ORDER BY t.priority ASC, at.tag_name ASC",
            agent_ids,
        ).fetchall()
        result: dict[str, list[dict]] = {aid: [] for aid in agent_ids}
        for r in rows:
            result[r["agent_id"]].append({"tag_name": r["tag_name"], "color": r["color"], "priority": r["priority"]})
        return result

    # ── Tag Policies ──

    def get_tag_policy(self, tag_name: str) -> dict[str, str]:
        rows = self._conn().execute(
            "SELECT setting_key, setting_value FROM tag_policies WHERE tag_name = ?",
            (tag_name,),
        ).fetchall()
        return {r["setting_key"]: r["setting_value"] for r in rows}

    def set_tag_policy(self, tag_name: str, overrides: dict[str, str]) -> None:
        conn = self._conn()
        tag = conn.execute("SELECT 1 FROM tags WHERE tag_name = ?", (tag_name,)).fetchone()
        if not tag:
            raise ValueError(f"Tag does not exist: {tag_name!r}")
        valid = {k: v for k, v in overrides.items() if k in _VALID_AGENT_SETTINGS}
        now = int(time.time())
        conn.execute("DELETE FROM tag_policies WHERE tag_name = ?", (tag_name,))
        for key, value in valid.items():
            conn.execute(
                "INSERT INTO tag_policies (tag_name, setting_key, setting_value, updated_at) VALUES (?, ?, ?, ?)",
                (tag_name, key, str(value), now),
            )
        conn.commit()

    # ── Tag Rules ──

    def set_tag_rules(self, tag_name: str, rules: list[dict]) -> None:
        """Replace all rules for a tag with validated new ones."""
        conn = self._conn()
        tag = conn.execute("SELECT 1 FROM tags WHERE tag_name = ?", (tag_name,)).fetchone()
        if not tag:
            raise ValueError(f"Tag does not exist: {tag_name!r}")
        # Validate rules before deleting existing ones
        valid_rules = []
        for r in rules:
            action = r.get("action", "")
            stage = r.get("stage", "")
            rule_type = r.get("rule_type", "")
            pattern = r.get("pattern", "")
            if action not in _VALID_RULE_ACTIONS:
                continue
            if stage not in _VALID_RULE_STAGES:
                continue
            if rule_type not in _VALID_RULE_TYPES:
                continue
            if not pattern:
                continue
            valid_rules.append(r)
        now = int(time.time())
        conn.execute("DELETE FROM tag_rules WHERE tag_name = ?", (tag_name,))
        for r in valid_rules:
            conn.execute(
                "INSERT INTO tag_rules (tag_name, action, stage, rule_type, pattern, chain_filter, description, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (tag_name, r["action"], r["stage"], r["rule_type"], r["pattern"], r.get("chain_filter", ""), r.get("description", ""), now),
            )
        conn.commit()

    def get_tag_rules(self, tag_name: str) -> list[dict]:
        """Get all rules for a tag."""
        rows = self._conn().execute(
            "SELECT action, stage, rule_type, pattern, chain_filter, description FROM tag_rules WHERE tag_name = ? ORDER BY id",
            (tag_name,),
        ).fetchall()
        return [dict(r) for r in rows]

    def resolve_agent_rules(self, agent_id: str) -> list[dict]:
        """Resolve all rules for an agent: global rules + rules from all assigned tags."""
        rules = list(self._global_rules)
        rows = self._conn().execute(
            "SELECT tr.action, tr.stage, tr.rule_type, tr.pattern, tr.chain_filter, tr.description "
            "FROM agent_tags at "
            "JOIN tag_rules tr ON at.tag_name = tr.tag_name "
            "WHERE at.agent_id = ? "
            "ORDER BY tr.id",
            (agent_id,),
        ).fetchall()
        rules.extend(dict(r) for r in rows)
        return rules

    # ── Config Resolution ──

    def resolve_agent_config(self, agent_id: str) -> dict:
        base: dict = self.get_agent_defaults()
        rows = self._conn().execute(
            "SELECT tp.setting_key, tp.setting_value "
            "FROM agent_tags at "
            "JOIN tags t ON at.tag_name = t.tag_name "
            "JOIN tag_policies tp ON at.tag_name = tp.tag_name "
            "WHERE at.agent_id = ? "
            "ORDER BY t.priority ASC, t.tag_name ASC",
            (agent_id,),
        ).fetchall()
        for r in rows:
            base[r["setting_key"]] = r["setting_value"]
        base["rules"] = self.resolve_agent_rules(agent_id)
        return base

    # ── XDR Federated Queries ──

    def enqueue_xdr_query(self, query_id: str, agent_id: str, finding_id: str, query_type: str, params_json: str) -> None:
        """Insert a pending federated query for delivery to an agent."""
        conn = self._conn()
        now = int(time.time())
        conn.execute(
            "INSERT OR IGNORE INTO xdr_queries (query_id, agent_id, finding_id, query_type, params_json, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (query_id, agent_id, finding_id, query_type, params_json, now),
        )
        conn.commit()

    def get_pending_queries_for_agent(self, agent_id: str) -> list[dict]:
        """Return pending queries for delivery via heartbeat."""
        rows = self._conn().execute(
            "SELECT query_id, query_type, params_json FROM xdr_queries WHERE agent_id = ? AND status = 'pending'",
            (agent_id,),
        ).fetchall()
        import json as _json
        result = []
        for r in rows:
            entry = {"query_id": r["query_id"], "query_type": r["query_type"]}
            try:
                entry["params"] = _json.loads(r["params_json"])
            except (ValueError, TypeError):
                entry["params"] = {}
            result.append(entry)
        return result

    def complete_xdr_query(self, query_id: str, result_json: str) -> dict | None:
        """Mark a query completed with results.

        Returns dict with {agent_id, finding_id, query_type} on success, None otherwise.
        """
        conn = self._conn()
        row = conn.execute(
            "SELECT agent_id, finding_id, query_type FROM xdr_queries WHERE query_id = ? AND status = 'pending'",
            (query_id,),
        ).fetchone()
        if not row:
            return None
        now = int(time.time())
        conn.execute(
            "UPDATE xdr_queries SET status = 'completed', result_json = ?, completed_at = ? "
            "WHERE query_id = ? AND status = 'pending'",
            (result_json, now, query_id),
        )
        conn.commit()
        return {"agent_id": row["agent_id"], "finding_id": row["finding_id"], "query_type": row["query_type"]}

    def get_xdr_result(self, finding_id: str, query_type: str) -> dict | None:
        """Get query status/result for a finding. Returns {status, result_json} or None."""
        row = self._conn().execute(
            "SELECT status, result_json FROM xdr_queries WHERE finding_id = ? AND query_type = ? ORDER BY created_at DESC LIMIT 1",
            (finding_id, query_type),
        ).fetchone()
        return dict(row) if row else None

    # ── Surveillance Log Storage ──

    def upsert_surveillance_logs(self, incident_id: str, agent_id: str, side: str, records: list[dict]) -> int:
        """Insert surveillance log records, deduplicating via original_log_id.

        Returns count of newly inserted rows.
        """
        conn = self._conn()
        now = int(time.time())
        rows_before = conn.execute(
            "SELECT COUNT(*) AS cnt FROM incident_surveillance_logs WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()["cnt"]
        conn.executemany(
            "INSERT OR IGNORE INTO incident_surveillance_logs "
            "(incident_id, agent_id, side, original_log_id, timestamp, event_type, "
            "process_name, pid, username, cmd_line, remote_ip, remote_port, details_json, ingested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    incident_id, agent_id, side,
                    r.get("id", 0),
                    r.get("timestamp", 0),
                    r.get("event_type", ""),
                    r.get("process_name"),
                    r.get("pid"),
                    r.get("username"),
                    r.get("cmd_line"),
                    r.get("remote_ip"),
                    r.get("remote_port"),
                    None,
                    now,
                )
                for r in records
            ],
        )
        conn.commit()
        rows_after = conn.execute(
            "SELECT COUNT(*) AS cnt FROM incident_surveillance_logs WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()["cnt"]
        return rows_after - rows_before

    def get_surveillance_logs(self, incident_id: str) -> dict:
        """Get surveillance logs partitioned by side.

        Returns {"dst_logs": [...], "src_logs": [...]}.
        """
        rows = self._conn().execute(
            "SELECT side, original_log_id, timestamp, event_type, process_name, pid, "
            "username, cmd_line, remote_ip, remote_port "
            "FROM incident_surveillance_logs WHERE incident_id = ? ORDER BY timestamp DESC",
            (incident_id,),
        ).fetchall()
        dst_logs: list[dict] = []
        src_logs: list[dict] = []
        for r in rows:
            entry = {
                "id": r["original_log_id"],
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "process_name": r["process_name"],
                "pid": r["pid"],
                "username": r["username"],
                "cmd_line": r["cmd_line"],
                "remote_ip": r["remote_ip"],
                "remote_port": r["remote_port"],
            }
            if r["side"] == "dst":
                dst_logs.append(entry)
            else:
                src_logs.append(entry)
        return {"dst_logs": dst_logs, "src_logs": src_logs}

    def get_surveillance_pull_state(self, incident_id: str, side: str) -> dict:
        """Get pull state for an incident side. Returns defaults if not found."""
        row = self._conn().execute(
            "SELECT last_enqueue_at, last_record_ts FROM surveillance_pull_state "
            "WHERE incident_id = ? AND side = ?",
            (incident_id, side),
        ).fetchone()
        if row:
            return {"last_enqueue_at": row["last_enqueue_at"], "last_record_ts": row["last_record_ts"]}
        return {"last_enqueue_at": 0, "last_record_ts": 0.0}

    def set_surveillance_pull_state(
        self, incident_id: str, side: str,
        last_enqueue_at: int | None = None,
        last_record_ts: float | None = None,
    ) -> None:
        """Upsert pull state. Uses MAX for last_record_ts to avoid regression."""
        conn = self._conn()
        conn.execute(
            "INSERT INTO surveillance_pull_state (incident_id, side, last_enqueue_at, last_record_ts) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(incident_id, side) DO UPDATE SET "
            "last_enqueue_at = CASE WHEN ? IS NOT NULL THEN ? ELSE surveillance_pull_state.last_enqueue_at END, "
            "last_record_ts = CASE WHEN ? IS NOT NULL THEN MAX(surveillance_pull_state.last_record_ts, ?) "
            "ELSE surveillance_pull_state.last_record_ts END",
            (
                incident_id, side,
                last_enqueue_at or 0, last_record_ts or 0.0,
                last_enqueue_at, last_enqueue_at,
                last_record_ts, last_record_ts,
            ),
        )
        conn.commit()

    def has_pending_xdr_query(self, finding_id: str, query_type: str) -> bool:
        """Check if there's a pending XDR query for this finding_id and query_type."""
        row = self._conn().execute(
            "SELECT 1 FROM xdr_queries WHERE finding_id = ? AND query_type = ? AND status = 'pending' LIMIT 1",
            (finding_id, query_type),
        ).fetchone()
        return row is not None

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
