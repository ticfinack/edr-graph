"""Kuzu connection management — single shared reader + private writer.

kuzu.Database is thread-safe and shared across all threads.
kuzu.Connection is NOT thread-safe, and Kuzu 0.11.x's buffer pool
cannot handle concurrent connections without SEGV.

Strategy:
  - ONE reader connection shared across all reader threads, protected
    by a threading.RLock via a LockedConnection proxy.
  - The graph-writer thread creates its OWN private connection via
    get_writer_connection() — no lock needed because it's the only
    thread that ever calls it.
"""
from __future__ import annotations

import threading

import kuzu

_db: kuzu.Database | None = None

# Single shared reader connection + reentrant lock
_reader_conn: kuzu.Connection | None = None
_reader_lock = threading.RLock()

# Private writer connection (used only by graph_writer_thread)
_writer_conn: kuzu.Connection | None = None


class LockedConnection:
    """Proxy around kuzu.Connection that acquires a lock on execute().

    The lock is held for the entire execute() + result iteration cycle.
    Callers MUST fully consume the QueryResult before the next execute()
    call from another thread can proceed.
    """

    def __init__(self, conn: kuzu.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def execute(self, query: str, parameters: dict | None = None) -> kuzu.QueryResult:
        with self._lock:
            result = self._conn.execute(query, parameters) if parameters is not None else self._conn.execute(query)
            # Materialize all rows under the lock to prevent interleaving
            return _MaterializedResult(result)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


class _MaterializedResult:
    """Pre-fetched query result that can be iterated without holding the lock."""

    def __init__(self, result: kuzu.QueryResult) -> None:
        self._rows: list[list] = []
        self._idx = 0
        while result.has_next():
            self._rows.append(result.get_next())

    def has_next(self) -> bool:
        return self._idx < len(self._rows)

    def get_next(self) -> list:
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def get_num_tuples(self) -> int:
        return len(self._rows)


# Singleton locked reader proxy
_locked_reader: LockedConnection | None = None


def init(db: kuzu.Database) -> None:
    """Store the shared Database reference. Call once at startup.

    Clears any stale connections from a previous db
    (relevant in test suites that create fresh databases per test).
    """
    global _db, _reader_conn, _writer_conn, _locked_reader
    _db = db
    _reader_conn = None
    _writer_conn = None
    _locked_reader = None


def get_connection() -> LockedConnection:
    """Return the shared, lock-protected reader connection.

    All reader threads (dashboard, analyzer, federated queries, init)
    share this single connection.  The LockedConnection proxy acquires
    the reader lock on each execute() call and materializes results,
    so callers don't need to manage locking themselves.
    """
    global _reader_conn, _locked_reader
    if _db is None:
        raise RuntimeError("Kuzu database not initialized — call connection.init() first")
    if _locked_reader is None:
        _reader_conn = kuzu.Connection(_db)
        _locked_reader = LockedConnection(_reader_conn, _reader_lock)
    return _locked_reader


def get_writer_connection() -> kuzu.Connection:
    """Return the private writer connection (graph-writer thread only).

    Creates the connection on first call.  No lock — only the single
    graph-writer thread should ever call this.
    """
    global _writer_conn
    if _db is None:
        raise RuntimeError("Kuzu database not initialized — call connection.init() first")
    if _writer_conn is None:
        _writer_conn = kuzu.Connection(_db)
    return _writer_conn
