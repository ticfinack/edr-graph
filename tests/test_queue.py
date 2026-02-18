"""Tests for SQLite queue."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from agent.queue.sqlite_queue import SqliteQueue
from agent.schema.graph_types import ChainStep, SecurityFinding


@pytest.fixture
def queue(tmp_path):
    q = SqliteQueue(tmp_path / "test.db")
    yield q
    q.close()


def _make_raw_event(**overrides):
    event = {
        "timestamp": datetime.now().isoformat(),
        "source": "test",
        "message": "test event",
        "fields": {},
        "hostname": "testhost",
    }
    event.update(overrides)
    return json.dumps(event)


class TestPushPop:
    def test_push_returns_id(self, queue):
        row_id = queue.push(_make_raw_event())
        assert row_id >= 1

    def test_pop_batch_returns_unprocessed(self, queue):
        queue.push(_make_raw_event(message="first"))
        queue.push(_make_raw_event(message="second"))
        batch = queue.pop_batch(10)
        assert len(batch) == 2
        assert batch[0][1]["message"] == "first"
        assert batch[1][1]["message"] == "second"

    def test_pop_batch_respects_limit(self, queue):
        for i in range(5):
            queue.push(_make_raw_event(message=f"event-{i}"))
        batch = queue.pop_batch(3)
        assert len(batch) == 3

    def test_fifo_order(self, queue):
        for i in range(5):
            queue.push(_make_raw_event(message=f"event-{i}"))
        batch = queue.pop_batch(5)
        for i, (_, data) in enumerate(batch):
            assert data["message"] == f"event-{i}"

    def test_push_many(self, queue):
        events = [_make_raw_event(message=f"bulk-{i}") for i in range(10)]
        queue.push_many(events)
        batch = queue.pop_batch(20)
        assert len(batch) == 10


class TestMarkProcessed:
    def test_mark_processed_excludes_from_pop(self, queue):
        queue.push(_make_raw_event(message="first"))
        queue.push(_make_raw_event(message="second"))
        batch = queue.pop_batch(10)
        queue.mark_processed([batch[0][0]])
        remaining = queue.pop_batch(10)
        assert len(remaining) == 1
        assert remaining[0][1]["message"] == "second"

    def test_count_unprocessed(self, queue):
        queue.push(_make_raw_event())
        queue.push(_make_raw_event())
        assert queue.count_unprocessed() == 2
        batch = queue.pop_batch(1)
        queue.mark_processed([batch[0][0]])
        assert queue.count_unprocessed() == 1


class TestFindings:
    def _make_finding(self, **overrides):
        data = dict(
            id="test-finding-1",
            timestamp=datetime(2025, 1, 15, 10, 0, 0),
            severity="high",
            title="Suspicious process",
            description="A suspicious process was detected",
            affected_entities=["user:alice", "process:curl"],
            evidence_event_ids=[1, 2, 3],
            recommendation="Investigate immediately",
            chain=[
                ChainStep(entity_type="user", entity_id="alice", entity_name="alice"),
                ChainStep(entity_type="process", entity_id="host:123:0", entity_name="curl"),
                ChainStep(entity_type="ip", entity_id="10.0.0.5", entity_name="10.0.0.5"),
            ],
        )
        data.update(overrides)
        return SecurityFinding(**data)

    def test_store_and_retrieve(self, queue):
        finding = self._make_finding()
        queue.store_finding(finding)
        results = queue.get_findings()
        assert len(results) == 1
        assert results[0].id == "test-finding-1"
        assert results[0].severity == "high"
        assert len(results[0].chain) == 3

    def test_filter_by_severity(self, queue):
        queue.store_finding(self._make_finding(id="f1", severity="high"))
        queue.store_finding(self._make_finding(id="f2", severity="low"))
        high = queue.get_findings(severity="high")
        assert len(high) == 1
        assert high[0].id == "f1"

    def test_findings_in_range(self, queue):
        queue.store_finding(
            self._make_finding(id="f1", timestamp=datetime(2025, 1, 15, 10, 0))
        )
        queue.store_finding(
            self._make_finding(id="f2", timestamp=datetime(2025, 1, 16, 10, 0))
        )
        results = queue.get_findings_in_range(
            datetime(2025, 1, 15), datetime(2025, 1, 15, 23, 59)
        )
        assert len(results) == 1
        assert results[0].id == "f1"


class TestRecentEvents:
    def test_get_recent_events(self, queue):
        queue.push(_make_raw_event(message="recent"))
        events = queue.get_recent_events(10)
        assert len(events) == 1
        assert events[0]["message"] == "recent"
        assert "_queue_id" in events[0]
