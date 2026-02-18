"""Thread-safe SQLite FIFO queue for raw events and findings storage."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from agent.schema.graph_types import SecurityFinding
from agent.schema.queue_schema import init_queue_db


class SqliteQueue:
    """Thread-safe SQLite-backed event queue and findings store.

    Each thread must call _get_conn() to get a thread-local connection.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        # Initialize schema on the first connection
        conn = self._get_conn()
        init_queue_db(conn)

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
        return self._local.conn

    def push(self, raw_json: str) -> int:
        """Push a raw event JSON string onto the queue. Returns the row ID."""
        conn = self._get_conn()
        cursor = conn.execute(
            "INSERT INTO event_queue (raw_json) VALUES (?)", (raw_json,)
        )
        conn.commit()
        return cursor.lastrowid

    def push_many(self, events: list[str]) -> None:
        """Push multiple raw event JSON strings in a single transaction."""
        conn = self._get_conn()
        conn.executemany(
            "INSERT INTO event_queue (raw_json) VALUES (?)",
            [(e,) for e in events],
        )
        conn.commit()

    def pop_batch(self, batch_size: int = 100) -> list[tuple[int, dict]]:
        """Pop a batch of unprocessed events. Returns list of (id, parsed_json)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, raw_json FROM event_queue "
            "WHERE processed = 0 ORDER BY id ASC LIMIT ?",
            (batch_size,),
        ).fetchall()
        return [(row["id"], json.loads(row["raw_json"])) for row in rows]

    def mark_processed(self, event_ids: list[int]) -> None:
        """Mark events as processed."""
        if not event_ids:
            return
        conn = self._get_conn()
        placeholders = ",".join("?" for _ in event_ids)
        conn.execute(
            f"UPDATE event_queue SET processed = 1 WHERE id IN ({placeholders})",
            event_ids,
        )
        conn.commit()

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """Get recent events for dashboard display."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, raw_json, created_at, processed FROM event_queue "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for row in rows:
            data = json.loads(row["raw_json"])
            data["_queue_id"] = row["id"]
            data["_created_at"] = row["created_at"]
            data["_processed"] = bool(row["processed"])
            results.append(data)
        return results

    def get_processed_since(self, since_id: int, limit: int = 100) -> list[tuple[int, dict]]:
        """Get processed events since a given ID (for analyzer)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, raw_json FROM event_queue "
            "WHERE processed = 1 AND id > ? ORDER BY id ASC LIMIT ?",
            (since_id, limit),
        ).fetchall()
        return [(row["id"], json.loads(row["raw_json"])) for row in rows]

    # --- Findings ---

    def store_finding(self, finding: SecurityFinding) -> None:
        """Store a security finding."""
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO findings "
            "(id, timestamp, severity, title, description, "
            "affected_entities, evidence_event_ids, recommendation, chain) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                finding.timestamp.isoformat(),
                finding.severity,
                finding.title,
                finding.description,
                json.dumps(finding.affected_entities),
                json.dumps(finding.evidence_event_ids),
                finding.recommendation,
                json.dumps([step.model_dump(mode="json") for step in finding.chain]),
            ),
        )
        conn.commit()

    def get_findings(
        self, limit: int = 50, severity: str | None = None
    ) -> list[SecurityFinding]:
        """Retrieve findings, optionally filtered by severity."""
        conn = self._get_conn()
        if severity:
            rows = conn.execute(
                "SELECT * FROM findings WHERE severity = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def get_findings_in_range(
        self, start: datetime, end: datetime
    ) -> list[SecurityFinding]:
        """Get findings within a time range (for Sankey)."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings "
            "WHERE timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp DESC",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> SecurityFinding:
        from agent.schema.graph_types import ChainStep

        return SecurityFinding(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            affected_entities=json.loads(row["affected_entities"]),
            evidence_event_ids=json.loads(row["evidence_event_ids"]),
            recommendation=row["recommendation"],
            chain=[ChainStep(**s) for s in json.loads(row["chain"])],
        )

    def count_unprocessed(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM event_queue WHERE processed = 0"
        ).fetchone()
        return row["cnt"]

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
