"""Prometheus metric definitions for the EDR agent."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

events_processed_total = Counter(
    "edr_events_processed_total",
    "Total events successfully processed",
    ["source", "event_type"],
)

events_dropped_total = Counter(
    "edr_events_dropped_total",
    "Total events dropped",
    ["source", "reason"],
)

event_processing_latency = Histogram(
    "edr_event_processing_latency_seconds",
    "Time to process a single event (normalize + extract + graph write)",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

llm_call_latency = Histogram(
    "edr_llm_call_latency_seconds",
    "Time for a single LLM API call",
    buckets=(0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

llm_verdicts = Counter(
    "edr_llm_verdicts_total",
    "LLM finding verdicts by severity",
    ["severity"],
)

agent_uptime = Gauge(
    "edr_agent_uptime_seconds",
    "Agent uptime in seconds",
)

queue_depth = Gauge(
    "edr_queue_depth",
    "Number of unprocessed events in the queue",
)
