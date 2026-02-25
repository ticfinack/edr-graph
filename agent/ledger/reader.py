"""Read-only query interface for the forensic ledger.

Opens its own WAL connection for concurrent reads while the writer
thread holds the write connection.  All queries return ``LedgerRow``
namedtuples with both raw columns and deserialized OCSF/entities.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
from collections import namedtuple
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("agent.ledger.reader")

LedgerRow = namedtuple("LedgerRow", [
    "id", "ts", "event_type", "hostname", "pid", "parent_pid",
    "process_name", "username", "remote_ip", "remote_port",
    "ocsf_json", "entities_json", "ocsf", "entities",
])


class LedgerReader:
    """Read-only query interface to the forensic ledger SQLite database."""

    def __init__(self, data_dir: Path) -> None:
        self._db_path = data_dir / "forensic_ledger.db"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_ledger_row(self, row: sqlite3.Row, deserialize: bool = True) -> LedgerRow:
        ocsf = None
        entities = None
        if deserialize:
            try:
                from agent.ledger.serializer import deserialize_entities, deserialize_ocsf
                if row["ocsf_json"]:
                    ocsf = deserialize_ocsf(row["ocsf_json"])
                if row["entities_json"]:
                    entities = deserialize_entities(row["entities_json"])
            except Exception:
                logger.debug("Deserialization failed for row %d", row["id"], exc_info=True)

        return LedgerRow(
            id=row["id"],
            ts=row["ts"],
            event_type=row["event_type"],
            hostname=row["hostname"],
            pid=row["pid"],
            parent_pid=row["parent_pid"],
            process_name=row["process_name"],
            username=row["username"],
            remote_ip=row["remote_ip"],
            remote_port=row["remote_port"],
            ocsf_json=row["ocsf_json"],
            entities_json=row["entities_json"],
            ocsf=ocsf,
            entities=entities,
        )

    def query_time_range(
        self,
        start: float,
        end: float,
        event_types: list[str] | None = None,
        limit: int = 1000,
    ) -> list[LedgerRow]:
        """Query events within a time range, optionally filtered by event type."""
        conn = self._connect()
        try:
            if event_types:
                placeholders = ", ".join("?" for _ in event_types)
                sql = (
                    f"SELECT * FROM forensic_ledger "
                    f"WHERE ts >= ? AND ts <= ? AND event_type IN ({placeholders}) "
                    f"ORDER BY ts DESC LIMIT ?"
                )
                params = [start, end] + event_types + [limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE ts >= ? AND ts <= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [start, end, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def query_by_pid(self, pid: int, since: float | None = None, limit: int = 500) -> list[LedgerRow]:
        """Query events for a specific PID."""
        conn = self._connect()
        try:
            if since is not None:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE pid = ? AND ts >= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [pid, since, limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE pid = ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [pid, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def query_by_ip(self, ip: str, since: float | None = None, limit: int = 500) -> list[LedgerRow]:
        """Query events involving a specific remote IP."""
        conn = self._connect()
        try:
            if since is not None:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE remote_ip = ? AND ts >= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [ip, since, limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE remote_ip = ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [ip, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Return ledger statistics: row count, oldest/newest ts, DB size."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*), MIN(ts), MAX(ts) FROM forensic_ledger"
            ).fetchone()
            db_size = 0
            with contextlib.suppress(OSError):
                db_size = os.path.getsize(str(self._db_path))

            return {
                "row_count": row[0] or 0,
                "oldest_ts": row[1],
                "newest_ts": row[2],
                "db_size_bytes": db_size,
            }
        finally:
            conn.close()

    def iter_entities(self, start: float, end: float) -> Iterator:
        """Yield deserialized ExtractedEntities for a time range.

        Used by the slicer to bulk-read entities for graph rebuilding.
        Streams results to avoid loading all rows into memory at once.
        """
        from agent.ledger.serializer import deserialize_entities

        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        try:
            cursor = conn.execute(
                "SELECT entities_json FROM forensic_ledger "
                "WHERE ts >= ? AND ts <= ? AND entities_json IS NOT NULL "
                "ORDER BY ts ASC",
                (start, end),
            )
            while True:
                row = cursor.fetchone()
                if row is None:
                    break
                try:
                    yield deserialize_entities(row[0])
                except Exception:
                    logger.debug("Failed to deserialize entities row", exc_info=True)
        finally:
            conn.close()
