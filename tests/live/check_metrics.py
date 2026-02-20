#!/usr/bin/env python3
"""Metrics dashboard: polls /metrics and prints a human-readable summary.

Usage:
    python tests/live/check_metrics.py [--port 9100] [--interval 5]

Continuously polls the Prometheus metrics endpoint and displays a live
dashboard in the terminal. Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import json
import time
from urllib.error import URLError
from urllib.request import urlopen

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

DEFAULT_PORT = 9100
DEFAULT_INTERVAL = 5


def fetch_metrics(port: int) -> str | None:
    """Fetch raw Prometheus metrics text."""
    try:
        with urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
            return resp.read().decode()
    except (URLError, OSError):
        return None


def fetch_health(port: int) -> dict | None:
    """Fetch health endpoint JSON."""
    try:
        with urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (URLError, OSError, json.JSONDecodeError):
        return None


class MetricsParser:
    """Parse Prometheus text format into a dict of metric values."""

    def __init__(self, text: str) -> None:
        self._lines = text.splitlines()
        self._cache: dict[str, list[tuple[dict[str, str], float]]] = {}
        self._parse()

    def _parse(self) -> None:
        for line in self._lines:
            if line.startswith("#") or not line.strip():
                continue

            # Parse "metric_name{label1="val1",label2="val2"} value" or "metric_name value"
            if "{" in line:
                name_end = line.index("{")
                labels_end = line.index("}")
                name = line[:name_end]
                labels_str = line[name_end + 1 : labels_end]
                value_str = line[labels_end + 1 :].strip()

                labels = {}
                if labels_str:
                    for part in labels_str.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            labels[k.strip()] = v.strip().strip('"')
            else:
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                labels = {}
                value_str = parts[1]

            try:
                value = float(value_str)
            except ValueError:
                continue

            self._cache.setdefault(name, []).append((labels, value))

    def get(self, name: str, labels: dict[str, str] | None = None) -> float | None:
        """Get a single metric value, optionally filtered by labels."""
        entries = self._cache.get(name, [])
        for entry_labels, value in entries:
            if labels is None or all(entry_labels.get(k) == v for k, v in labels.items()):
                return value
        return None

    def sum(self, name: str) -> float:
        """Sum all label variants of a metric."""
        total = 0.0
        for _, value in self._cache.get(name, []):
            total += value
        return total

    def get_all(self, name: str) -> list[tuple[dict[str, str], float]]:
        """Get all (labels, value) pairs for a metric."""
        return self._cache.get(name, [])

    def get_histogram_quantile(self, name: str, quantile: float) -> float | None:
        """Estimate a histogram quantile from bucket data."""
        buckets = self.get_all(name + "_bucket")
        if not buckets:
            return None

        # Sort by le (upper bound)
        sorted_buckets = []
        for labels, count in buckets:
            le = labels.get("le", "+Inf")
            le_val = float("inf") if le == "+Inf" else float(le)
            sorted_buckets.append((le_val, count))
        sorted_buckets.sort(key=lambda x: x[0])

        if not sorted_buckets:
            return None

        total = sorted_buckets[-1][1]
        if total == 0:
            return None

        target = quantile * total
        prev_count = 0.0
        prev_bound = 0.0

        for bound, count in sorted_buckets:
            if count >= target:
                # Linear interpolation within bucket
                if count == prev_count:
                    return bound
                fraction = (target - prev_count) / (count - prev_count)
                return prev_bound + fraction * (bound - prev_bound)
            prev_count = count
            prev_bound = bound

        return sorted_buckets[-1][0]


def format_latency(seconds: float | None) -> str:
    """Format latency in human-readable form."""
    if seconds is None:
        return "N/A"
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f}us"
    if seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    return f"{seconds:.2f}s"


def colorize_value(value: float, warn_threshold: float, crit_threshold: float) -> str:
    """Colorize a value based on thresholds (higher = worse)."""
    if value >= crit_threshold:
        return f"{RED}{value:.0f}{RESET}"
    if value >= warn_threshold:
        return f"{YELLOW}{value:.0f}{RESET}"
    return f"{GREEN}{value:.0f}{RESET}"


def print_dashboard(
    metrics: MetricsParser,
    health: dict | None,
    prev_metrics: MetricsParser | None,
    dt: float,
) -> None:
    """Print the metrics dashboard."""
    # Clear screen
    print("\033[2J\033[H", end="")

    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}        EDR Agent Metrics Dashboard{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")

    # Basic info
    uptime = metrics.get("edr_agent_uptime_seconds") or 0
    queue = metrics.get("edr_queue_depth") or 0
    events_total = metrics.sum("edr_events_processed_total")
    events_dropped = metrics.sum("edr_events_dropped_total")

    print(f"  {BOLD}Uptime:{RESET}            {uptime:.0f}s")
    print(f"  {BOLD}Events processed:{RESET}  {events_total:.0f}")
    dropped_str = colorize_value(events_dropped, 1, 10)
    print(f"  {BOLD}Events dropped:{RESET}    {dropped_str}")

    # Event rate (from deltas)
    if prev_metrics and dt > 0:
        prev_events = prev_metrics.sum("edr_events_processed_total")
        rate = (events_total - prev_events) / dt
        print(f"  {BOLD}Event rate:{RESET}        {rate:.1f} events/sec")
    else:
        if uptime > 0:
            rate = events_total / uptime
            print(f"  {BOLD}Event rate (avg):{RESET} {rate:.1f} events/sec")

    queue_str = colorize_value(queue, 5000, 8000)
    print(f"  {BOLD}Queue depth:{RESET}       {queue_str}")

    # Health status
    if health:
        status = health.get("status", "unknown")
        if status == "healthy":
            print(f"  {BOLD}Health:{RESET}            {GREEN}{status}{RESET}")
        else:
            print(f"  {BOLD}Health:{RESET}            {RED}{status}{RESET}")
    else:
        print(f"  {BOLD}Health:{RESET}            {RED}unreachable{RESET}")

    # Processing latency
    print(f"\n  {BOLD}--- Processing Latency ---{RESET}")
    p50 = metrics.get_histogram_quantile("edr_event_processing_latency_seconds", 0.5)
    p95 = metrics.get_histogram_quantile("edr_event_processing_latency_seconds", 0.95)
    p99 = metrics.get_histogram_quantile("edr_event_processing_latency_seconds", 0.99)
    print(f"  Event processing (p50/p95/p99): {format_latency(p50)} / {format_latency(p95)} / {format_latency(p99)}")

    # LLM latency
    llm_p50 = metrics.get_histogram_quantile("edr_llm_call_latency_seconds", 0.5)
    llm_p95 = metrics.get_histogram_quantile("edr_llm_call_latency_seconds", 0.95)
    llm_p99 = metrics.get_histogram_quantile("edr_llm_call_latency_seconds", 0.99)
    print(
        f"  LLM call (p50/p95/p99):         "
        f"{format_latency(llm_p50)} / {format_latency(llm_p95)} / {format_latency(llm_p99)}"
    )

    # Attack chain latency
    chain_p50 = metrics.get_histogram_quantile("edr_attack_chain_build_latency_seconds", 0.5)
    chain_p95 = metrics.get_histogram_quantile("edr_attack_chain_build_latency_seconds", 0.95)
    if chain_p50 is not None or chain_p95 is not None:
        print(f"  Attack chain build (p50/p95):    {format_latency(chain_p50)} / {format_latency(chain_p95)}")

    # LLM verdicts
    print(f"\n  {BOLD}--- LLM Verdicts ---{RESET}")
    severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    verdict_parts = []
    for sev in severities:
        val = metrics.get("edr_llm_verdicts_total", {"severity": sev}) or 0
        if sev in ("HIGH", "CRITICAL") and val > 0:
            verdict_parts.append(f"{RED}{sev}={val:.0f}{RESET}")
        elif sev == "MEDIUM" and val > 0:
            verdict_parts.append(f"{YELLOW}{sev}={val:.0f}{RESET}")
        else:
            verdict_parts.append(f"{sev}={val:.0f}")
    print(f"  LLM verdicts: {'  '.join(verdict_parts)}")

    # DGA detections
    dga_total = metrics.get("edr_dga_detections_total") or 0
    print(f"  DGA detections: {dga_total:.0f}")

    # Persistence detections
    persist_entries = metrics.get_all("edr_persistence_detections_total")
    persist_total = sum(v for _, v in persist_entries)
    print(f"  Persistence detections: {persist_total:.0f}")

    # Response actions
    response_entries = metrics.get_all("edr_response_actions_total")
    response_total = sum(v for _, v in response_entries)
    print(f"  Response actions: {response_total:.0f}")

    # Tamper checks
    tamper_checks = metrics.get("edr_tamper_checks_total") or 0
    tamper_detections = metrics.sum("edr_tamper_detections_total")
    if tamper_checks > 0 or tamper_detections > 0:
        print(f"  Tamper checks: {tamper_checks:.0f}  detections: {tamper_detections:.0f}")

    # Event sources breakdown
    print(f"\n  {BOLD}--- Event Sources ---{RESET}")
    source_entries = metrics.get_all("edr_events_processed_total")
    source_totals: dict[str, float] = {}
    for labels, value in source_entries:
        source = labels.get("source", "unknown")
        source_totals[source] = source_totals.get(source, 0) + value
    for source in sorted(source_totals.keys()):
        print(f"  {source}: {source_totals[source]:.0f}")

    print(f"\n  {DIM}Press Ctrl+C to stop{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(description="EDR Agent Metrics Dashboard")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Metrics port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Poll interval in seconds (default: {DEFAULT_INTERVAL})",
    )
    args = parser.parse_args()

    print(f"Polling http://127.0.0.1:{args.port}/metrics every {args.interval}s...")
    print("Waiting for agent to respond...\n")

    prev_metrics: MetricsParser | None = None
    prev_time = time.time()

    try:
        while True:
            metrics_text = fetch_metrics(args.port)
            health_data = fetch_health(args.port)

            if metrics_text is None:
                print(f"  {RED}Cannot reach metrics endpoint on port {args.port}. Is the agent running?{RESET}")
                time.sleep(args.interval)
                continue

            current_time = time.time()
            dt = current_time - prev_time
            metrics = MetricsParser(metrics_text)

            print_dashboard(metrics, health_data, prev_metrics, dt)

            prev_metrics = metrics
            prev_time = current_time
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n\nStopped.")


if __name__ == "__main__":
    main()
