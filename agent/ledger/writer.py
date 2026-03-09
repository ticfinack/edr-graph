"""Forensic ledger: append-only SQLite WAL for ALL OCSF telemetry.

Tier 1 of the capture architecture — records every event with 0% drop
rate.  Under memory pressure, collectors continue collecting and the
ledger continues recording.  The graph (Tier 3) can be rebuilt from this
ledger at any time.

Design constraints:
  - Writes are non-blocking: callers enqueue via ``record()``, a
    background thread batches inserts every ~0.5 s.
  - Configurable TTL (default 24h): ``_prune()`` runs every 60 s.
  - WAL mode + synchronous=OFF for maximum throughput.
  - Queue: 50K maxsize.  If full, block briefly (0.1 s) then drop.
  - DB file lives at ``{data_dir}/forensic_ledger.db``.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path

from agent.ledger.serializer import serialize_entities, serialize_ocsf

logger = logging.getLogger("agent.ledger.writer")

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS forensic_ledger (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    event_type   TEXT    NOT NULL,
    hostname     TEXT,
    pid          INTEGER,
    parent_pid   INTEGER,
    process_name TEXT,
    username     TEXT,
    remote_ip    TEXT,
    remote_port  INTEGER,
    ocsf_json    TEXT    NOT NULL,
    entities_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_ledger_ts   ON forensic_ledger (ts);
CREATE INDEX IF NOT EXISTS idx_ledger_pid  ON forensic_ledger (pid);
CREATE INDEX IF NOT EXISTS idx_ledger_ip   ON forensic_ledger (remote_ip);
CREATE INDEX IF NOT EXISTS idx_ledger_user ON forensic_ledger (username);
CREATE INDEX IF NOT EXISTS idx_ledger_type ON forensic_ledger (event_type);
"""

_FLUSH_INTERVAL = 0.5
_MAX_BATCH = 512
_PRUNE_INTERVAL = 60.0


class LedgerWriter:
    """Non-blocking, append-only forensic ledger."""

    def __init__(self, data_dir: Path | str, ttl_hours: int = 24, queue_size: int = 50_000) -> None:
        self._data_dir = Path(data_dir).resolve()
        self._db_path = self._data_dir / "forensic_ledger.db"
        self._ttl_seconds = ttl_hours * 3600
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._queue: queue.Queue[tuple] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()

        # Initialize schema on main thread
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA cache_size=-8000")  # 8 MB page cache limit
        conn.executescript(_SCHEMA)
        conn.close()

        self._thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="forensic-ledger",
        )
        self._thread.start()
        logger.info("Forensic ledger started (%s, ttl=%dh)", self._db_path, ttl_hours)

    def record(self, ocsf, entities, event_id: int) -> None:
        """Non-blocking enqueue of an OCSF event + extracted entities."""
        try:
            event_type = type(ocsf).__name__
            ts = ocsf.time.timestamp() if ocsf.time else time.time()

            # Extract denormalized columns
            hostname = getattr(getattr(ocsf, "device", None), "hostname", None)
            proc = getattr(ocsf, "process", None)
            pid = proc.pid if proc else None
            parent_pid = getattr(proc, "parent_pid", None) if proc else None
            process_name = proc.name if proc else None

            # Username
            username = None
            if entities.users:
                username = entities.users[0].name or entities.users[0].id
            elif hasattr(ocsf, "user"):
                username = getattr(ocsf.user, "name", None)

            # Remote IP / port
            remote_ip = None
            remote_port = None
            if entities.ips:
                remote_ip = entities.ips[0].address
                for edge in entities.connected_edges:
                    if edge.get("ip_id") == remote_ip:
                        remote_port = edge.get("dst_port")
                        break
            elif hasattr(ocsf, "dst_endpoint") and ocsf.dst_endpoint:
                remote_ip = ocsf.dst_endpoint.ip or None
                remote_port = ocsf.dst_endpoint.port or None
            elif hasattr(ocsf, "src_endpoint") and ocsf.src_endpoint:
                remote_ip = ocsf.src_endpoint.ip or None

            ocsf_json = serialize_ocsf(ocsf)
            entities_json = serialize_entities(entities)

            row = (
                ts, event_type, hostname, pid, parent_pid,
                process_name, username, remote_ip, remote_port,
                ocsf_json, entities_json,
            )

            # Try non-blocking first, then brief block, then drop
            try:
                self._queue.put_nowait(row)
            except queue.Full:
                try:
                    self._queue.put(row, timeout=0.1)
                except queue.Full:
                    logger.warning("Forensic ledger queue full, dropping event %d", event_id)
        except Exception:
            logger.debug("Forensic ledger record failed", exc_info=True)

    def stop(self) -> None:
        """Flush remaining events and stop the writer thread."""
        self._stop.set()
        self._thread.join(timeout=5.0)

    @property
    def db_path(self) -> Path:
        return self._db_path

    # ── Background writer ───────────────────────────────────────────

    def _writer_loop(self) -> None:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA cache_size=-8000")  # 8 MB page cache limit
        last_prune = time.monotonic()
        try:
            while not self._stop.is_set():
                batch = self._drain_queue()
                if batch:
                    self._insert_batch(conn, batch)
                now = time.monotonic()
                if now - last_prune > _PRUNE_INTERVAL:
                    last_prune = now
                    self._prune(conn)
                self._stop.wait(timeout=_FLUSH_INTERVAL)
            # Final flush
            batch = self._drain_queue()
            if batch:
                self._insert_batch(conn, batch)
        finally:
            conn.close()

    def _drain_queue(self) -> list[tuple]:
        batch: list[tuple] = []
        while len(batch) < _MAX_BATCH:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    @staticmethod
    def _insert_batch(conn: sqlite3.Connection, batch: list[tuple]) -> None:
        try:
            conn.executemany(
                "INSERT INTO forensic_ledger "
                "(ts, event_type, hostname, pid, parent_pid, "
                "process_name, username, remote_ip, remote_port, "
                "ocsf_json, entities_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
            conn.commit()
            from agent.metrics import ledger_events_written
            ledger_events_written.inc(len(batch))
        except Exception:
            logger.debug("Forensic ledger batch insert failed", exc_info=True)

    def _prune(self, conn: sqlite3.Connection) -> None:
        cutoff = time.time() - self._ttl_seconds
        try:
            cur = conn.execute(
                "DELETE FROM forensic_ledger WHERE ts < ?", (cutoff,),
            )
            conn.commit()
            if cur.rowcount:
                logger.debug("Forensic ledger pruned %d stale rows", cur.rowcount)
        except Exception:
            logger.debug("Forensic ledger prune failed", exc_info=True)
        # Update DB size metric
        try:
            from agent.metrics import ledger_db_size_mb
            ledger_db_size_mb.set(self._db_path.stat().st_size / (1024 * 1024))
        except Exception:
            pass
