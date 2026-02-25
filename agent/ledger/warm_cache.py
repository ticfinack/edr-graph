"""Background-rebuilt warm Kuzu graph for the dashboard.

WarmGraph maintains a periodically rebuilt transient Kuzu graph from the
forensic ledger.  Dashboard endpoints call ``get_connection()`` and get
back a connection to the latest warm graph — transparent to existing
query code.

Uses a double-buffer pattern: a new graph is built in a fresh tmpdir,
then atomically swapped in.  The old graph is cleaned up after swap.

Bulk ingest via CSV + COPY FROM makes rebuilds fast (~seconds, not minutes).
"""

from __future__ import annotations

import contextlib
import gc
import glob
import logging
import os
import shutil
import tempfile
import threading
import time

import kuzu

from agent.ledger.reader import LedgerReader
from agent.schema.kuzu_schema import init_graph_schema

logger = logging.getLogger("agent.ledger.warm_cache")


class WarmGraph:
    """Background-rebuilt warm Kuzu graph for dashboard endpoints."""

    def __init__(
        self,
        ledger_reader: LedgerReader,
        window_hours: float = 2.0,
        first_window_hours: float = 0.25,
        rebuild_interval_s: float = 300.0,
        buffer_pool_mb: int = 128,
    ) -> None:
        self._reader = ledger_reader
        self._window_hours = window_hours
        self._first_window_hours = first_window_hours
        self._rebuild_interval = rebuild_interval_s
        self._buffer_pool_mb = buffer_pool_mb

        self._lock = threading.Lock()
        self._current_conn: kuzu.Connection | None = None
        self._current_db: kuzu.Database | None = None
        self._current_tmpdir: str | None = None

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._first_rebuild = True

    def start(self) -> None:
        """Start background rebuild thread. Returns immediately."""
        # Clean up stale tmpdirs from previous runs
        self._cleanup_stale_tmpdirs()

        self._thread = threading.Thread(
            target=self._rebuild_loop, daemon=True, name="warm-graph",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop rebuild thread and clean up."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)
        self._cleanup_current()

    def wait_ready(self, timeout: float = 120.0) -> bool:
        """Block until the first rebuild completes. Returns True if ready."""
        return self._ready.wait(timeout=timeout)

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

        # Adaptive window: short first rebuild for fast dashboard availability
        if self._first_rebuild:
            window_h = self._first_window_hours
            self._first_rebuild = False
        else:
            window_h = self._window_hours
        start = now - (window_h * 3600)

        tmpdir = tempfile.mkdtemp(prefix="edr-kuzu-")
        csv_dir = os.path.join(tmpdir, "csv")
        os.makedirs(csv_dir)
        db_path = os.path.join(tmpdir, "db")

        try:
            # Phase 1: Export deduplicated entities from ledger to CSV
            t_export = time.monotonic()
            csv_files = self._reader.export_entities_csv(start, now, csv_dir)
            export_elapsed = time.monotonic() - t_export

            if not csv_files:
                logger.info("Warm graph rebuild: no entities in window (%.1fh)", window_h)
                shutil.rmtree(tmpdir, ignore_errors=True)
                return

            # Phase 2: Create Kuzu DB and schema
            db = kuzu.Database(
                db_path,
                buffer_pool_size=self._buffer_pool_mb * 1024 * 1024,
            )
            conn = kuzu.Connection(db)
            init_graph_schema(conn)

            # Phase 3: Bulk load via COPY FROM (nodes first, then edges)
            t_load = time.monotonic()
            node_tables = ("User", "Process", "IP", "Domain", "File", "RegistryKey")
            loaded = 0
            for table in node_tables:
                csv_path = csv_files.get(table)
                if csv_path:
                    conn.execute(f"COPY {table} FROM '{csv_path}' (HEADER=true)")
                    loaded += 1

            # Edges (order doesn't matter, nodes already loaded)
            edge_tables = (
                "SPAWNED", "CONNECTED_TO", "RESOLVED", "RESOLVES_TO",
                "CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE",
                "CREATED_REG", "MODIFIED_REG", "DELETED_REG", "LISTENING_ON",
            )
            for table in edge_tables:
                csv_path = csv_files.get(table)
                if csv_path:
                    try:
                        conn.execute(f"COPY {table} FROM '{csv_path}' (HEADER=true)")
                        loaded += 1
                    except Exception:
                        logger.debug("COPY FROM failed for %s", table, exc_info=True)

            load_elapsed = time.monotonic() - t_load
            total_elapsed = time.monotonic() - t0

            # Update metrics
            try:
                from agent.metrics import transient_graph_build_latency, warm_graph_rebuild_count
                warm_graph_rebuild_count.inc()
                transient_graph_build_latency.observe(total_elapsed)
            except Exception:
                pass

            logger.info(
                "Warm graph rebuilt: %d tables loaded in %.1fs "
                "(export=%.1fs, load=%.1fs, window=%.1fh, total=%.1fs)",
                loaded, load_elapsed, export_elapsed, load_elapsed, window_h, total_elapsed,
            )

            # Atomic swap
            old_tmpdir = None
            with self._lock:
                old_tmpdir = self._current_tmpdir
                self._current_conn = conn
                self._current_db = db
                self._current_tmpdir = tmpdir

            # Cleanup old graph (but not the new tmpdir!)
            if old_tmpdir is not None:
                try:
                    shutil.rmtree(old_tmpdir, ignore_errors=True)
                except Exception:
                    logger.debug("Failed to remove old warm graph tmpdir", exc_info=True)

        except Exception:
            # On failure, clean up the new tmpdir
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

    def _cleanup_current(self) -> None:
        with self._lock:
            self._current_conn = None
            if self._current_db is not None:
                del self._current_db
                self._current_db = None
            gc.collect()  # Free Kuzu buffer pool memory promptly
            if self._current_tmpdir is not None:
                with contextlib.suppress(Exception):
                    shutil.rmtree(self._current_tmpdir, ignore_errors=True)
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
