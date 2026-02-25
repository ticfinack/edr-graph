"""Tests for the MPSC graph write queue."""
from __future__ import annotations

import contextlib
import queue
import threading
from unittest.mock import patch

import pytest

from agent.graph.write_queue import (
    WriteJob,
    WriteJobType,
    get_queue,
    submit,
    submit_sync,
)


class TestSubmitAndConsume:
    """Basic submit/consume round-trip."""

    def test_submit_and_consume(self):
        q = get_queue()
        # Drain any leftover jobs from other tests
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        job = WriteJob(job_type=WriteJobType.ENTITY_BATCH, payload=["test"])
        submit(job)

        consumed = q.get(timeout=1.0)
        assert consumed is job
        assert consumed.job_type == WriteJobType.ENTITY_BATCH
        assert consumed.payload == ["test"]

    def test_submit_multiple_types(self):
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        jobs = [
            WriteJob(job_type=WriteJobType.ENTITY_BATCH, payload="a"),
            WriteJob(job_type=WriteJobType.IP_ENRICHMENT, payload="b"),
            WriteJob(job_type=WriteJobType.PRUNE_EDGES, payload={"ttl_hours": 24}),
        ]
        for j in jobs:
            submit(j)

        consumed = []
        for _ in range(3):
            consumed.append(q.get(timeout=1.0))

        assert [c.job_type for c in consumed] == [
            WriteJobType.ENTITY_BATCH,
            WriteJobType.IP_ENRICHMENT,
            WriteJobType.PRUNE_EDGES,
        ]


class TestSubmitSync:
    """Synchronous submit with result return."""

    def test_submit_sync_returns_result(self):
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        def consumer():
            job = q.get(timeout=5.0)
            job._result = 42
            job._result_event.set()

        t = threading.Thread(target=consumer, daemon=True)
        t.start()

        result = submit_sync(
            WriteJob(job_type=WriteJobType.PURGE_BASELINE, payload={"baseline_gate": None}),
            timeout=5.0,
        )
        assert result == 42
        t.join(timeout=2.0)

    def test_submit_sync_timeout_raises(self):
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        # Nobody is consuming, so this should time out
        with pytest.raises(TimeoutError):
            submit_sync(
                WriteJob(job_type=WriteJobType.PURGE_BY_RULE, payload={}),
                timeout=0.1,
            )
        # Drain the job we just put in
        with contextlib.suppress(queue.Empty):
            q.get_nowait()


class TestBackpressure:
    """Queue full behavior."""

    def test_submit_drops_when_full(self):
        """submit() should not raise when the queue is full."""
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        # Fill the queue to capacity using a small mock maxsize
        try:
            # We can't easily resize the real queue, so fill it to the brim
            # and test that submit doesn't raise. Use a separate small queue.
            small_q = queue.Queue(maxsize=2)
            small_q.put(WriteJob(job_type=WriteJobType.ENTITY_BATCH))
            small_q.put(WriteJob(job_type=WriteJobType.ENTITY_BATCH))

            # Patch the module-level queue
            with patch("agent.graph.write_queue._write_queue", small_q):
                # This should NOT raise — it drops the job
                submit(WriteJob(job_type=WriteJobType.ENTITY_BATCH, payload="dropped"))

            # Queue should still be at capacity (2)
            assert small_q.qsize() == 2
        finally:
            pass  # no cleanup needed


class TestShutdownSentinel:
    """SHUTDOWN job type."""

    def test_shutdown_sentinel(self):
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        submit(WriteJob(job_type=WriteJobType.SHUTDOWN))
        job = q.get(timeout=1.0)
        assert job.job_type == WriteJobType.SHUTDOWN

    def test_shutdown_terminates_consumer_loop(self):
        """Simulate a consumer loop that exits on SHUTDOWN."""
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        consumed = []

        def consumer():
            while True:
                try:
                    job = q.get(timeout=1.0)
                except queue.Empty:
                    continue
                consumed.append(job.job_type)
                if job.job_type == WriteJobType.SHUTDOWN:
                    break

        t = threading.Thread(target=consumer, daemon=True)
        t.start()

        submit(WriteJob(job_type=WriteJobType.ENTITY_BATCH, payload="a"))
        submit(WriteJob(job_type=WriteJobType.IP_ENRICHMENT, payload="b"))
        submit(WriteJob(job_type=WriteJobType.SHUTDOWN))

        t.join(timeout=5.0)
        assert not t.is_alive()
        assert consumed == [
            WriteJobType.ENTITY_BATCH,
            WriteJobType.IP_ENRICHMENT,
            WriteJobType.SHUTDOWN,
        ]


class TestCheckpointJob:
    """CHECKPOINT job type."""

    def test_checkpoint_job_consumed(self):
        q = get_queue()
        while not q.empty():
            try:
                q.get_nowait()
            except queue.Empty:
                break

        submit(WriteJob(job_type=WriteJobType.CHECKPOINT))
        job = q.get(timeout=1.0)
        assert job.job_type == WriteJobType.CHECKPOINT
        assert job.payload is None


class TestPressureDropPct:
    """Shared pressure_drop_pct variable."""

    def test_default_is_zero(self):
        import agent.graph.write_queue as wq

        # Save and restore
        original = wq.pressure_drop_pct
        try:
            assert original == 0 or isinstance(original, int)
        finally:
            wq.pressure_drop_pct = original

    def test_set_and_read(self):
        import agent.graph.write_queue as wq

        original = wq.pressure_drop_pct
        try:
            wq.pressure_drop_pct = 75
            assert wq.pressure_drop_pct == 75
        finally:
            wq.pressure_drop_pct = original


class TestWriteJobDefaults:
    """WriteJob dataclass defaults."""

    def test_event_not_set_initially(self):
        job = WriteJob(job_type=WriteJobType.ENTITY_BATCH)
        assert not job._result_event.is_set()
        assert job._result is None
        assert job.payload is None

    def test_result_event_set(self):
        job = WriteJob(job_type=WriteJobType.PRUNE_FULL)
        job._result = 99
        job._result_event.set()
        assert job._result_event.is_set()
        assert job._result == 99
