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

events_self_filtered = Counter(
    "edr_events_self_filtered_total",
    "Entities filtered by agent self-allowlist",
)

events_allowlist_filtered = Counter(
    "edr_events_allowlist_filtered_total",
    "Entities filtered by allowlist before graph insertion",
)

edges_baseline_gated = Counter(
    "edr_edges_baseline_gated_total",
    "Edges filtered by baseline gating before graph insertion",
)

events_fast_blocked = Counter(
    "edr_events_fast_blocked_total",
    "Events blocked by synchronous fast-path blocklist enforcer",
)

dga_detections_total = Counter(
    "edr_dga_detections_total",
    "Total DGA candidate domain detections",
)

persistence_detections_total = Counter(
    "edr_persistence_detections_total",
    "Total persistence mechanism detections",
    ["persistence_type"],
)

attack_chain_build_latency = Histogram(
    "edr_attack_chain_build_latency_seconds",
    "Time to build a full attack chain context",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

response_actions_total = Counter(
    "edr_response_actions_total",
    "Total response actions taken",
    ["action", "result"],
)

tamper_checks_total = Counter(
    "edr_tamper_checks_total",
    "Total tamper detection checks performed",
)

tamper_detections_total = Counter(
    "edr_tamper_detections_total",
    "Total tamper events detected",
    ["event_type"],
)

agent_uptime = Gauge(
    "edr_agent_uptime_seconds",
    "Agent uptime in seconds",
)

queue_depth = Gauge(
    "edr_queue_depth",
    "Number of unprocessed events in the queue",
)

# Fleet forwarding metrics
fleet_items_forwarded = Counter(
    "edr_fleet_items_forwarded_total",
    "Total items forwarded to fleet server",
    ["item_type"],
)

fleet_forwarding_errors = Counter(
    "edr_fleet_forwarding_errors_total",
    "Total forwarding errors",
    ["error_type"],
)

fleet_forwarding_queue_depth = Gauge(
    "edr_fleet_forwarding_queue_depth",
    "Number of items pending in the forwarding queue",
)

graph_reaper_pruned = Counter(
    "edr_graph_reaper_pruned_total",
    "Graph edges and nodes pruned by TTL reaper",
)

graph_db_size_mb = Gauge(
    "edr_graph_db_size_mb",
    "Graph database directory size in MB",
)

graph_reaper_emergency_prunes = Counter(
    "edr_graph_reaper_emergency_prunes_total",
    "Number of emergency pressure-driven edge-only prunes",
)

graph_rss_mb = Gauge(
    "edr_graph_rss_mb",
    "Process RSS in MB",
)

graph_pressure_level = Gauge(
    "edr_graph_pressure_level",
    "Memory pressure level (0=normal, 1=warning, 2=high, 3=critical)",
)

events_pressure_dropped = Counter(
    "edr_events_pressure_dropped_total",
    "Write batches dropped due to memory pressure throttling",
)

fleet_forwarding_latency = Histogram(
    "edr_fleet_forwarding_latency_seconds",
    "Time to forward a batch to fleet server",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Forensic ledger metrics
ledger_events_written = Counter(
    "edr_ledger_events_written_total",
    "Total events written to the forensic ledger",
)

ledger_db_size_mb = Gauge(
    "edr_ledger_db_size_mb",
    "Forensic ledger SQLite database size in MB",
)

transient_graph_build_latency = Histogram(
    "edr_transient_graph_build_latency_seconds",
    "Time to build a transient Kuzu graph from ledger",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

warm_graph_rebuild_count = Counter(
    "edr_warm_graph_rebuild_total",
    "Number of warm graph rebuilds completed",
)
