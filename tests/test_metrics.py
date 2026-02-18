"""Tests for Prometheus metrics and health endpoint."""

import json
import urllib.request

import pytest
from prometheus_client import CollectorRegistry

from agent.metrics import (
    events_processed_total,
    events_dropped_total,
    event_processing_latency,
    llm_verdicts,
    queue_depth,
)
from agent.health import start_health_server


class TestMetricDefinitions:
    def test_counter_increments(self):
        before = events_processed_total.labels(source="test", event_type="process")._value.get()
        events_processed_total.labels(source="test", event_type="process").inc()
        after = events_processed_total.labels(source="test", event_type="process")._value.get()
        assert after == before + 1

    def test_histogram_observe(self):
        event_processing_latency.observe(0.042)
        # Should not raise

    def test_verdict_counter(self):
        before = llm_verdicts.labels(severity="high")._value.get()
        llm_verdicts.labels(severity="high").inc()
        after = llm_verdicts.labels(severity="high")._value.get()
        assert after == before + 1

    def test_queue_depth_gauge(self):
        queue_depth.set(42)
        assert queue_depth._value.get() == 42


@pytest.fixture(scope="module")
def health_server():
    """Start health server on an ephemeral port for testing."""
    # Use port 0 to get a random available port
    server = start_health_server(port=0, queue_depth_fn=lambda: 7)
    port = server.server_address[1]
    yield port
    server.shutdown()


class TestHealthEndpoint:
    def test_health_json(self, health_server):
        port = health_server
        url = f"http://127.0.0.1:{port}/health"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert data["queue_depth"] == 7

    def test_metrics_text(self, health_server):
        port = health_server
        url = f"http://127.0.0.1:{port}/metrics"
        with urllib.request.urlopen(url) as resp:
            body = resp.read().decode()
        assert "edr_events_processed_total" in body
        assert "edr_agent_uptime_seconds" in body
