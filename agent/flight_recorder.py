"""Local flight recorder: SQLite-backed continuous DVR for incident forensics.

Records ALL telemetry to a rolling buffer (default 6 hours).  When the fleet
server requests logs, the agent queries this historical buffer to reconstruct
attacker footprints retroactively — eliminating the "time-to-arm" blindspot.

Design constraints:
  - Writes are non-blocking: callers enqueue dicts, a background thread batches
    them into SQLite every ~0.5 s.
  - Configurable TTL (default 6h): ``_prune()`` runs once per writer cycle.
  - WAL mode for concurrent read/write without blocking.
  - The DB file lives at ``{data_dir}/flight_recorder.db``.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("agent.flight_recorder")

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS surveillance_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    event_type  TEXT    NOT NULL,
    process_name TEXT,
    pid         INTEGER,
    username    TEXT,
    cmd_line    TEXT,
    remote_ip   TEXT,
    remote_port INTEGER,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_surv_ts ON surveillance_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_surv_ip ON surveillance_logs (remote_ip);
CREATE INDEX IF NOT EXISTS idx_surv_user ON surveillance_logs (username);
CREATE INDEX IF NOT EXISTS idx_surv_pid ON surveillance_logs (pid);
"""

_UID_ALIASES: dict[str, list[str]] = {
    "root": ["0"],
    "0": ["root"],
    "nobody": ["65534"],
    "65534": ["nobody"],
}

_FLUSH_INTERVAL = 0.5  # seconds between batch writes
_MAX_BATCH = 256

# OS background noise process names squelched from ALL surveillance queries.
# These generate high-volume telemetry with zero forensic value.
_SQUELCH_PROCESS_NAMES = (
    "kworker/%",  # Linux kernel workers (LIKE pattern)
)
_SQUELCH_EXACT_NAMES = frozenset({
    "containerd-shim-runc-v2",
    "docker-proxy",
    "sleep",
    "watchdog.sh",
    "runningboardd",
    "com.apple.WebKit.Networking",
    "Mail",
    "healthcheck.sh",
    "cypher-shell",
    "java",
    "check_dns.sh",
    "dockerd",
})


class FlightRecorder:
    """Non-blocking, SQLite-backed continuous DVR surveillance log."""

    def __init__(self, data_dir: Path, ttl_hours: int = 6) -> None:
        self._db_path = data_dir / "flight_recorder.db"
        self._ttl_seconds = ttl_hours * 3600
        data_dir.mkdir(parents=True, exist_ok=True)

        self._queue: queue.Queue[dict] = queue.Queue(maxsize=10_000)
        self._stop = threading.Event()

        # Initialise schema on the main thread so callers know the DB is ready
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_SCHEMA)
        conn.close()

        self._thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="flight-recorder",
        )
        self._thread.start()
        logger.info("Flight recorder started (%s, ttl=%dh)", self._db_path, ttl_hours)

    # ── Public API ──────────────────────────────────────────────────

    def record(self, event: dict) -> None:
        """Enqueue a surveillance event (non-blocking, drops if queue full)."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.debug("Flight recorder queue full, dropping event")

    def query(
        self,
        ip: str | None = None,
        username: str | None = None,
        pids: list[int] | None = None,
        since: float | None = None,
        limit: int = 200,
    ) -> list[dict]:
        """Read-only query against the surveillance log.

        Called by the ``pull_surveillance_logs`` federated query handler on the
        forwarder heartbeat thread — safe because SQLite supports concurrent readers.
        """
        clauses: list[str] = []
        params: list = []
        if ip:
            clauses.append("remote_ip = ?")
            params.append(ip)
        if username:
            aliases = _UID_ALIASES.get(username, [])
            if aliases:
                placeholders = ", ".join("?" for _ in [username] + aliases)
                clauses.append(f"username IN ({placeholders})")
                params.extend([username] + aliases)
            else:
                clauses.append("username = ?")
                params.append(username)
        if pids:
            placeholders = ", ".join("?" for _ in pids)
            clauses.append(f"pid IN ({placeholders})")
            params.extend(pids)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        # Squelch OS background noise from ALL surveillance queries
        like_parts = [f"process_name NOT LIKE ?" for _ in _SQUELCH_PROCESS_NAMES]
        exact_placeholders = ", ".join("?" for _ in _SQUELCH_EXACT_NAMES)
        squelch = (
            "(process_name IS NULL OR ("
            + " AND ".join(like_parts)
            + f" AND process_name NOT IN ({exact_placeholders})"
            + "))"
        )
        clauses.append(squelch)
        params.extend(_SQUELCH_PROCESS_NAMES)
        params.extend(_SQUELCH_EXACT_NAMES)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT id, timestamp, event_type, process_name, pid, username, "
            f"cmd_line, remote_ip, remote_port, details_json "
            f"FROM surveillance_logs {where} "
            f"ORDER BY timestamp DESC LIMIT ?"
        )
        params.append(limit)

        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def stop(self) -> None:
        """Flush remaining events and stop the writer thread."""
        self._stop.set()
        self._thread.join(timeout=3.0)

    # ── Background writer ───────────────────────────────────────────

    def _writer_loop(self) -> None:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        last_prune = time.monotonic()
        try:
            while not self._stop.is_set():
                batch = self._drain_queue()
                if batch:
                    self._insert_batch(conn, batch)
                # Periodic TTL prune (~every 60 s)
                now = time.monotonic()
                if now - last_prune > 60.0:
                    last_prune = now
                    self._prune(conn)
                self._stop.wait(timeout=_FLUSH_INTERVAL)
            # Final flush on shutdown
            batch = self._drain_queue()
            if batch:
                self._insert_batch(conn, batch)
        finally:
            conn.close()

    def _drain_queue(self) -> list[dict]:
        batch: list[dict] = []
        while len(batch) < _MAX_BATCH:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    @staticmethod
    def _insert_batch(conn: sqlite3.Connection, batch: list[dict]) -> None:
        try:
            conn.executemany(
                "INSERT INTO surveillance_logs "
                "(timestamp, event_type, process_name, pid, username, "
                "cmd_line, remote_ip, remote_port, details_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        e.get("timestamp", time.time()),
                        e.get("event_type", "unknown"),
                        e.get("process_name"),
                        e.get("pid"),
                        e.get("username"),
                        e.get("cmd_line"),
                        e.get("remote_ip"),
                        e.get("remote_port"),
                        e.get("details_json"),
                    )
                    for e in batch
                ],
            )
            conn.commit()
        except Exception:
            logger.debug("Flight recorder batch insert failed", exc_info=True)

    def _prune(self, conn: sqlite3.Connection) -> None:
        cutoff = time.time() - self._ttl_seconds
        try:
            cur = conn.execute(
                "DELETE FROM surveillance_logs WHERE timestamp < ?", (cutoff,),
            )
            conn.commit()
            if cur.rowcount:
                logger.debug("Flight recorder pruned %d stale rows", cur.rowcount)
        except Exception:
            logger.debug("Flight recorder prune failed", exc_info=True)
