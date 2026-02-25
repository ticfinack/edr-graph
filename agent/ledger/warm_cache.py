"""Background-rebuilt warm Kuzu graph for the dashboard.

WarmGraph maintains a periodically rebuilt transient Kuzu graph from the
forensic ledger.  Dashboard endpoints call ``get_connection()`` and get
back a connection to the latest warm graph — transparent to existing
query code.

Uses a double-buffer pattern: a new graph is built in a fresh tmpdir,
then atomically swapped in.  The old graph is cleaned up after swap.
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import tempfile
import threading
import time

import kuzu

from agent.ledger.reader import LedgerReader
from agent.processor.graph_builder import GraphBuilder
from agent.schema.kuzu_schema import init_graph_schema

logger = logging.getLogger("agent.ledger.warm_cache")


class WarmGraph:
    """Background-rebuilt warm Kuzu graph for dashboard endpoints."""

    def __init__(
        self,
        ledger_reader: LedgerReader,
        window_hours: float = 2.0,
        rebuild_interval_s: float = 300.0,
        buffer_pool_mb: int = 64,
    ) -> None:
        self._reader = ledger_reader
        self._window_hours = window_hours
        self._rebuild_interval = rebuild_interval_s
        self._buffer_pool_mb = buffer_pool_mb

        self._lock = threading.Lock()
        self._current_conn: kuzu.Connection | None = None
        self._current_db: kuzu.Database | None = None
        self._current_tmpdir: str | None = None

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        """Start background rebuild thread. Blocks until first build completes."""
        # Clean up stale tmpdirs from previous runs
        self._cleanup_stale_tmpdirs()

        self._thread = threading.Thread(
            target=self._rebuild_loop, daemon=True, name="warm-graph",
        )
        self._thread.start()
        # Block until first build completes
        self._ready.wait(timeout=120.0)

    def stop(self) -> None:
        """Stop rebuild thread and clean up."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)
        self._cleanup_current()

    def get_connection(self) -> kuzu.Connection:
        """Return connection to current warm graph (thread-safe)."""
        with self._lock:
            if self._current_conn is None:
                raise RuntimeError("Warm graph not initialized")
            return self._current_conn

    def _rebuild_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._rebuild()
            except Exception:
                logger.exception("Warm graph rebuild failed")
            if not self._ready.is_set():
                self._ready.set()
            self._stop.wait(timeout=self._rebuild_interval)

    def _rebuild(self) -> None:
        t0 = time.monotonic()
        now = time.time()
        start = now - (self._window_hours * 3600)

        tmpdir = tempfile.mkdtemp(prefix="edr-kuzu-")
        db_path = os.path.join(tmpdir, "db")
        db = kuzu.Database(
            db_path,
            buffer_pool_size=self._buffer_pool_mb * 1024 * 1024,
        )
        conn = kuzu.Connection(db)
        init_graph_schema(conn)

        builder = GraphBuilder(db, conn=conn)
        count = 0
        for entities in self._reader.iter_entities(start, now):
            builder.write_entities(entities)
            count += 1

        elapsed = time.monotonic() - t0
        logger.info(
            "Warm graph rebuilt: %d entity batches in %.1fs (window=%.1fh)",
            count, elapsed, self._window_hours,
        )

        # Atomic swap
        old_tmpdir = None
        with self._lock:
            old_tmpdir = self._current_tmpdir
            self._current_conn = conn
            self._current_db = db
            self._current_tmpdir = tmpdir

        # Cleanup old graph
        if old_tmpdir is not None:
            try:
                shutil.rmtree(old_tmpdir, ignore_errors=True)
            except Exception:
                logger.debug("Failed to remove old warm graph tmpdir", exc_info=True)

    def _cleanup_current(self) -> None:
        with self._lock:
            self._current_conn = None
            if self._current_db is not None:
                del self._current_db
                self._current_db = None
            if self._current_tmpdir is not None:
                try:
                    shutil.rmtree(self._current_tmpdir, ignore_errors=True)
                except Exception:
                    pass
                self._current_tmpdir = None

    @staticmethod
    def _cleanup_stale_tmpdirs() -> None:
        """Remove edr-kuzu-* tmpdirs older than 1 hour."""
        tmpdir_root = tempfile.gettempdir()
        cutoff = time.time() - 3600
        for path in glob.glob(os.path.join(tmpdir_root, "edr-kuzu-*")):
            try:
                mtime = os.path.getmtime(path)
                if mtime < cutoff and os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                    logger.debug("Cleaned up stale warm graph tmpdir: %s", path)
            except Exception:
                pass
