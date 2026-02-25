"""MPSC (Multi-Producer Single-Consumer) queue for graph writes.

All graph mutations (entity upserts, edge creation, TTL deletes,
baseline purges) flow through this queue and are consumed by a single
dedicated writer thread holding the only write-capable Kuzu connection.
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger("agent.graph.write_queue")


class WriteJobType(Enum):
    ENTITY_BATCH = auto()      # payload: list[ExtractedEntities]
    IP_ENRICHMENT = auto()     # payload: IpNode
    PRUNE_EDGES = auto()       # payload: {"ttl_hours": float}
    PRUNE_FULL = auto()        # payload: {"ttl_hours": float}
    PRUNE_HIGH_DEGREE = auto() # payload: {"edge_threshold": int, "keep_pct": float}
    PURGE_BASELINE = auto()    # payload: {"baseline_gate": BaselineGateCache}
    PURGE_BY_RULE = auto()     # payload: {"rule_type": str, "pattern": str}
    CHECKPOINT = auto()        # payload: None — flush WAL, release dirty pages
    SHUTDOWN = auto()


@dataclass
class WriteJob:
    job_type: WriteJobType
    payload: Any = None
    # For synchronous callers (dashboard API endpoints)
    _result_event: threading.Event = field(default_factory=threading.Event)
    _result: Any = None


# Module-level singleton queue (maxsize provides backpressure)
_write_queue: queue.Queue[WriteJob] = queue.Queue(maxsize=10_000)

# Deprecated: pressure_drop_pct and collector_paused removed.
# The forensic ledger (Tier 1) captures ALL telemetry — collectors never pause.
# Kept as no-op attributes for backwards compatibility with any external readers.
pressure_drop_pct: int = 0
collector_paused: bool = False


def submit(job: WriteJob) -> None:
    """Non-blocking submit. Drops job if queue is full (backpressure)."""
    try:
        _write_queue.put_nowait(job)
    except queue.Full:
        logger.warning("Write queue full (%d), dropping %s job",
                       _write_queue.qsize(), job.job_type.name)


def submit_sync(job: WriteJob, timeout: float = 30.0) -> Any:
    """Submit job and block until writer completes it. Returns the result.

    Used by dashboard purge endpoints that need a synchronous response.
    Raises TimeoutError if the writer doesn't complete within timeout.
    """
    _write_queue.put(job, timeout=timeout)
    if not job._result_event.wait(timeout=timeout):
        raise TimeoutError(f"Write job {job.job_type.name} timed out after {timeout}s")
    return job._result


def get_queue() -> queue.Queue[WriteJob]:
    """Return the singleton queue (used by the writer thread)."""
    return _write_queue
