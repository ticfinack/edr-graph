"""Tests for fleet forwarder: forwarding queue, drain logic, retry behavior."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent.config import Settings
from agent.queue.sqlite_queue import SqliteQueue
from agent.schema.graph_types import ChainStep, SecurityFinding


@pytest.fixture
def queue(tmp_path):
    q = SqliteQueue(tmp_path / "test.db")
    yield q
    q.close()


@pytest.fixture
def sample_finding():
    return SecurityFinding(
        id="finding-001",
        timestamp=datetime(2025, 1, 15, 10, 30, 0),
        severity="high",
        title="Suspicious outbound connection",
        description="Process curl connected to known C2 IP",
        affected_entities=["process:curl", "ip:10.0.0.1"],
        evidence_event_ids=[1, 2, 3],
        recommendation="Investigate and block",
        chain=[
            ChainStep(
                entity_type="process",
                entity_id="host:1234:0",
                entity_name="curl",
                pid=1234,
                timestamp=datetime(2025, 1, 15, 10, 30, 0),
            )
        ],
        affected_pids=[1234],
        iocs={"ips": ["10.0.0.1"], "domains": ["evil.com"]},
    )


class TestForwardingQueue:
    def test_push_and_pop_finding(self, queue, sample_finding):
        payload = sample_finding.model_dump_json()
        queue.push_forwarding("finding", payload)
        batch = queue.pop_forwarding_batch(batch_size=10)
        assert len(batch) == 1
        id_, item_type, item_payload = batch[0]
        assert item_type == "finding"
        assert json.loads(item_payload)["id"] == "finding-001"

    def test_push_and_pop_event(self, queue):
        event_json = json.dumps({"class_uid": 4001, "dst_endpoint": {"ip": "1.2.3.4"}})
        queue.push_forwarding("event", event_json)
        batch = queue.pop_forwarding_batch(batch_size=10)
        assert len(batch) == 1
        assert batch[0][1] == "event"

    def test_pop_respects_batch_size(self, queue):
        for i in range(10):
            queue.push_forwarding("finding", f'{{"id": "f-{i}"}}')
        batch = queue.pop_forwarding_batch(batch_size=3)
        assert len(batch) == 3

    def test_mark_forwarded_deletes_items(self, queue):
        queue.push_forwarding("finding", '{"id": "f-1"}')
        queue.push_forwarding("finding", '{"id": "f-2"}')
        batch = queue.pop_forwarding_batch(batch_size=10)
        ids = [b[0] for b in batch]
        queue.mark_forwarded(ids)
        remaining = queue.pop_forwarding_batch(batch_size=10)
        assert len(remaining) == 0

    def test_mark_forward_failed_increments_retry(self, queue):
        queue.push_forwarding("finding", '{"id": "f-1"}')
        batch = queue.pop_forwarding_batch(batch_size=10)
        ids = [b[0] for b in batch]
        queue.mark_forward_failed(ids, max_retries=5)
        # Item should still be there (retry_count=1 < max_retries=5)
        # But it's still 'pending' since we only increment retry_count
        remaining = queue.pop_forwarding_batch(batch_size=10)
        assert len(remaining) == 1

    def test_max_retries_deletes_item(self, queue):
        queue.push_forwarding("finding", '{"id": "f-1"}')
        batch = queue.pop_forwarding_batch(batch_size=10)
        ids = [b[0] for b in batch]
        # Fail max_retries + 1 times to exceed threshold
        for _ in range(6):
            queue.mark_forward_failed(ids, max_retries=5)
        remaining = queue.pop_forwarding_batch(batch_size=10)
        assert len(remaining) == 0

    def test_forwarding_queue_depth(self, queue):
        assert queue.forwarding_queue_depth() == 0
        queue.push_forwarding("finding", '{"id": "f-1"}')
        queue.push_forwarding("event", '{"class_uid": 1007}')
        assert queue.forwarding_queue_depth() == 2

    def test_empty_mark_forwarded_is_noop(self, queue):
        queue.mark_forwarded([])  # Should not raise

    def test_empty_mark_forward_failed_is_noop(self, queue):
        queue.mark_forward_failed([])  # Should not raise


class TestFleetForwarderIntegration:
    def test_forward_finding_queues_payload(self, queue, sample_finding):
        settings = Settings(fleet_enabled=True, fleet_url="localhost:50051")
        with patch("agent.fleet.forwarder.grpc") as mock_grpc:
            mock_channel = MagicMock()
            mock_grpc.insecure_channel.return_value = mock_channel
            mock_grpc.secure_channel.return_value = mock_channel

            from agent.fleet.forwarder import FleetForwarder

            forwarder = FleetForwarder(settings=settings, queue=queue)
            forwarder.forward_finding(sample_finding)

        batch = queue.pop_forwarding_batch(batch_size=10)
        assert len(batch) == 1
        assert batch[0][1] == "finding"
        data = json.loads(batch[0][2])
        assert data["id"] == "finding-001"
        assert data["severity"] == "high"

    def test_forward_events_queues_payloads(self, queue):
        settings = Settings(fleet_enabled=True, fleet_url="localhost:50051")
        with patch("agent.fleet.forwarder.grpc") as mock_grpc:
            mock_channel = MagicMock()
            mock_grpc.insecure_channel.return_value = mock_channel

            from agent.fleet.forwarder import FleetForwarder

            forwarder = FleetForwarder(settings=settings, queue=queue)
            events = ['{"class_uid": 4001}', '{"class_uid": 1007}']
            forwarder.forward_events(events)

        batch = queue.pop_forwarding_batch(batch_size=10)
        assert len(batch) == 2
        assert all(b[1] == "event" for b in batch)
