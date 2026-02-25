"""On-demand transient Kuzu graph built from forensic ledger data.

TransientGraph: context manager that builds a temporary Kuzu DB from a
time slice of the ledger, returns a connection for queries, and cleans
up the tmpdir on exit.

Uses CSV export + COPY FROM for fast bulk ingestion.

Used by the analyzer for attack chain building when kuzu_persistent_enabled=False.
"""

from __future__ import annotations

import gc
import logging
import os
import shutil
import tempfile
import time

import kuzu

from agent.ledger.reader import LedgerReader
from agent.schema.kuzu_schema import init_graph_schema

logger = logging.getLogger("agent.ledger.slicer")


class TransientGraph:
    """Context manager: build a temporary Kuzu graph from a ledger time slice.

    Usage::

        with TransientGraph(reader, start, end) as conn:
            result = conn.execute("MATCH (p:Process) RETURN p.name")
    """

    def __init__(
        self,
        ledger_reader: LedgerReader,
        start: float,
        end: float,
        buffer_pool_mb: int = 128,
    ) -> None:
        self._reader = ledger_reader
        self._start = start
        self._end = end
        self._buffer_pool_mb = buffer_pool_mb
        self._tmpdir: str | None = None
        self._db: kuzu.Database | None = None
        self._conn: kuzu.Connection | None = None

    def __enter__(self) -> kuzu.Connection:
        t0 = time.monotonic()
        self._tmpdir = tempfile.mkdtemp(prefix="edr-kuzu-")
        csv_dir = os.path.join(self._tmpdir, "csv")
        os.makedirs(csv_dir)
        db_path = os.path.join(self._tmpdir, "db")

        # Phase 1: Export entities to CSV
        csv_files = self._reader.export_entities_csv(self._start, self._end, csv_dir)

        # Phase 2: Create DB + schema
        self._db = kuzu.Database(
            db_path,
            buffer_pool_size=self._buffer_pool_mb * 1024 * 1024,
        )
        self._conn = kuzu.Connection(self._db)
        init_graph_schema(self._conn)

        # Phase 3: Bulk load via COPY FROM
        node_tables = ("User", "Process", "IP", "Domain", "File", "RegistryKey")
        loaded = 0
        for table in node_tables:
            csv_path = csv_files.get(table)
            if csv_path:
                self._conn.execute(f"COPY {table} FROM '{csv_path}' (HEADER=true)")
                loaded += 1

        edge_tables = (
            "SPAWNED", "CONNECTED_TO", "RESOLVED", "RESOLVES_TO",
            "CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE",
            "CREATED_REG", "MODIFIED_REG", "DELETED_REG", "LISTENING_ON",
        )
        for table in edge_tables:
            csv_path = csv_files.get(table)
            if csv_path:
                try:
                    self._conn.execute(f"COPY {table} FROM '{csv_path}' (HEADER=true)")
                    loaded += 1
                except Exception:
                    logger.debug("COPY FROM failed for %s", table, exc_info=True)

        elapsed = time.monotonic() - t0
        logger.info(
            "TransientGraph built: %d tables loaded in %.1fs, window=%.0fs",
            loaded, elapsed, self._end - self._start,
        )

        # Update metrics
        try:
            from agent.metrics import transient_graph_build_latency
            transient_graph_build_latency.observe(elapsed)
        except Exception:
            pass

        return self._conn

    def __exit__(self, *args) -> None:
        try:
            self._conn = None
            self._db = None
        except Exception:
            logger.debug("TransientGraph cleanup error", exc_info=True)
        # Force GC to free Kuzu buffer pool before removing files
        gc.collect()
        gc.collect()
        if self._tmpdir is not None:
            try:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                logger.debug("Failed to remove transient graph tmpdir", exc_info=True)
            self._tmpdir = None
