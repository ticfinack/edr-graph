"""On-demand transient Kuzu graph built from forensic ledger data.

TransientGraph: context manager that builds a temporary Kuzu DB from a
time slice of the ledger, returns a connection for queries, and cleans
up the tmpdir on exit.

Used by the analyzer for attack chain building when kuzu_persistent_enabled=False.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile

import kuzu

from agent.ledger.reader import LedgerReader
from agent.processor.graph_builder import GraphBuilder
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
        buffer_pool_mb: int = 64,
    ) -> None:
        self._reader = ledger_reader
        self._start = start
        self._end = end
        self._buffer_pool_mb = buffer_pool_mb
        self._tmpdir: str | None = None
        self._db: kuzu.Database | None = None
        self._conn: kuzu.Connection | None = None

    def __enter__(self) -> kuzu.Connection:
        self._tmpdir = tempfile.mkdtemp(prefix="edr-kuzu-")
        db_path = os.path.join(self._tmpdir, "db")
        self._db = kuzu.Database(
            db_path,
            buffer_pool_size=self._buffer_pool_mb * 1024 * 1024,
        )
        self._conn = kuzu.Connection(self._db)
        init_graph_schema(self._conn)

        builder = GraphBuilder(self._db, conn=self._conn)
        count = 0
        for entities in self._reader.iter_entities(self._start, self._end):
            builder.write_entities(entities)
            count += 1

        logger.info(
            "TransientGraph built: %d entity batches, window=%.0fs",
            count,
            self._end - self._start,
        )
        return self._conn

    def __exit__(self, *args) -> None:
        try:
            if self._conn is not None:
                self._conn = None
            if self._db is not None:
                del self._db
                self._db = None
        except Exception:
            logger.debug("TransientGraph cleanup error", exc_info=True)
        if self._tmpdir is not None:
            try:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                logger.debug("Failed to remove transient graph tmpdir", exc_info=True)
            self._tmpdir = None
