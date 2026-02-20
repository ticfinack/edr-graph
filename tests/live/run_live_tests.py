#!/usr/bin/env python3
"""Pre-flight runner: starts the agent and verifies health + metrics.

Usage:
    python tests/live/run_live_tests.py [--config tests/live/test_config.yaml]

This is NOT a unit test. It starts the real agent, waits for initialization,
checks the health and metrics endpoints, prints a summary, then waits for
Ctrl+C to shut down.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

DEFAULT_CONFIG = Path(__file__).parent / "test_config.yaml"
DEFAULT_METRICS_PORT = 9100
STARTUP_WAIT = 10  # seconds to wait for agent to initialize


def print_header(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")


def print_ok(text: str) -> None:
    print(f"  {GREEN}[OK]{RESET}   {text}")


def print_fail(text: str) -> None:
    print(f"  {RED}[FAIL]{RESET} {text}")


def print_warn(text: str) -> None:
    print(f"  {YELLOW}[WARN]{RESET} {text}")


def print_info(text: str) -> None:
    print(f"  {CYAN}[INFO]{RESET} {text}")


def check_health(port: int) -> dict | None:
    """Hit the /health endpoint and return parsed JSON, or None on failure."""
    url = f"http://127.0.0.1:{port}/health"
    try:
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data
    except (URLError, OSError, json.JSONDecodeError):
        return None


def check_metrics(port: int) -> str | None:
    """Hit the /metrics endpoint and return raw Prometheus text, or None."""
    url = f"http://127.0.0.1:{port}/metrics"
    try:
        with urlopen(url, timeout=5) as resp:
            return resp.read().decode()
    except (URLError, OSError):
        return None


def parse_metric_value(metrics_text: str, metric_name: str) -> float | None:
    """Extract a single metric value from Prometheus text format."""
    for line in metrics_text.splitlines():
        if line.startswith(metric_name) and not line.startswith(metric_name + "_"):
            # Handle metrics with no labels: "metric_name value"
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return float(parts[-1])
                except ValueError:
                    pass
        # Handle metrics with labels: "metric_name{labels} value"
        if line.startswith(metric_name + "{"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return float(parts[-1])
                except ValueError:
                    pass
    return None


def sum_metric_values(metrics_text: str, metric_name: str) -> float:
    """Sum all label variants of a metric."""
    total = 0.0
    for line in metrics_text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(metric_name + "{") or line.startswith(metric_name + " "):
            parts = line.split()
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    total += float(parts[-1])
    return total


def detect_collector_type(metrics_text: str) -> str:
    """Detect which collector is active from the source label in metrics."""
    sources = set()
    for line in metrics_text.splitlines():
        if line.startswith("edr_events_processed_total{"):
            # Extract source label value
            start = line.find('source="')
            if start >= 0:
                start += len('source="')
                end = line.find('"', start)
                if end > start:
                    sources.add(line[start:end])
    if not sources:
        return "none detected"
    return ", ".join(sorted(sources))


def run_preflight(config_path: Path, metrics_port: int) -> None:
    """Start the agent, run pre-flight checks, wait for Ctrl+C."""
    print_header("EDR Agent Pre-Flight Check")

    # Verify config file exists
    if not config_path.exists():
        print_fail(f"Config file not found: {config_path}")
        sys.exit(1)
    print_ok(f"Config file: {config_path}")

    # Build the agent command
    agent_cmd = [
        sys.executable,
        "-m",
        "agent.main",
        "--config",
        str(config_path),
        "--no-watchdog",
        "--no-tamper-check",
        "--no-dashboard",
        "--log-format",
        "text",
        "--log-level",
        "DEBUG",
        "--metrics-port",
        str(metrics_port),
    ]
    print_info(f"Command: {' '.join(agent_cmd)}")

    # Start the agent as a subprocess
    print_info("Starting agent...")
    env = os.environ.copy()
    # Ensure the project root is in PYTHONPATH
    project_root = Path(__file__).resolve().parent.parent.parent
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")

    agent_proc = subprocess.Popen(
        agent_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(project_root),
        env=env,
    )

    # Collect startup logs
    startup_logs: list[str] = []
    errors_found: list[str] = []

    print_info(f"Waiting {STARTUP_WAIT}s for initialization...")
    start_time = time.time()

    # Poll for health endpoint while collecting logs
    while time.time() - start_time < STARTUP_WAIT:
        # Non-blocking read of stdout
        if agent_proc.stdout and agent_proc.stdout.readable():
            import select

            ready, _, _ = select.select([agent_proc.stdout], [], [], 0.5)
            if ready:
                line = agent_proc.stdout.readline()
                if line:
                    startup_logs.append(line.rstrip())
                    if "error" in line.lower() or "exception" in line.lower():
                        errors_found.append(line.rstrip())
        else:
            time.sleep(0.5)

        # Check if process died
        if agent_proc.poll() is not None:
            print_fail(f"Agent exited with code {agent_proc.returncode}")
            for log_line in startup_logs[-20:]:
                print(f"    {log_line}")
            sys.exit(1)

        # Try health endpoint
        health = check_health(metrics_port)
        if health and health.get("status") == "healthy":
            break

    print_header("Pre-Flight Results")

    # Check 1: Agent started
    if agent_proc.poll() is None:
        print_ok(f"Agent process is running (PID {agent_proc.pid})")
    else:
        print_fail(f"Agent process died (exit code {agent_proc.returncode})")

    # Check 2: Health endpoint
    health_data = check_health(metrics_port)
    if health_data and health_data.get("status") == "healthy":
        uptime = health_data.get("uptime_seconds", 0)
        queue = health_data.get("queue_depth", -1)
        print_ok(f"/health returns healthy (uptime={uptime:.1f}s, queue_depth={queue})")
    else:
        print_fail(f"/health not responding on port {metrics_port}")

    # Check 3: Metrics endpoint
    metrics_text = check_metrics(metrics_port)
    if metrics_text:
        # Verify it's valid Prometheus text
        has_help = any(line.startswith("# HELP") for line in metrics_text.splitlines())
        has_type = any(line.startswith("# TYPE") for line in metrics_text.splitlines())
        if has_help and has_type:
            print_ok("/metrics returns valid Prometheus format")
        else:
            print_warn("/metrics returned data but may not be valid Prometheus format")

        # Summary metrics
        collector_type = detect_collector_type(metrics_text)
        events_total = sum_metric_values(metrics_text, "edr_events_processed_total")
        events_dropped = sum_metric_values(metrics_text, "edr_events_dropped_total")
        queue_depth_val = parse_metric_value(metrics_text, "edr_queue_depth")
        uptime_val = parse_metric_value(metrics_text, "edr_agent_uptime_seconds")

        print()
        print_header("Agent Summary")
        print_info(f"Collector sources: {collector_type}")
        print_info(f"Events processed:  {events_total:.0f}")
        print_info(f"Events dropped:    {events_dropped:.0f}")
        if queue_depth_val is not None:
            print_info(f"Queue depth:       {queue_depth_val:.0f}")
        if uptime_val is not None and uptime_val > 0:
            rate = events_total / uptime_val
            print_info(f"Event rate:        {rate:.1f} events/sec")

        if events_dropped > 0:
            print_warn("Some events were dropped! Check logs for details.")
    else:
        print_fail(f"/metrics not responding on port {metrics_port}")

    # Check 4: Startup errors
    if errors_found:
        print()
        print_warn(f"Found {len(errors_found)} error(s) in startup logs:")
        for err_line in errors_found[:10]:
            print(f"    {RED}{err_line}{RESET}")
    else:
        print_ok("No errors in startup logs")

    # Wait for Ctrl+C
    print()
    print_header("Agent Running")
    print_info("Press Ctrl+C to shut down the agent.")
    print_info(f"Health:  http://127.0.0.1:{metrics_port}/health")
    print_info(f"Metrics: http://127.0.0.1:{metrics_port}/metrics")
    print()

    # Continuous monitoring loop
    try:
        last_events = events_total if metrics_text else 0
        last_time = time.time()
        while True:
            time.sleep(10)
            # Check agent is still alive
            if agent_proc.poll() is not None:
                print_fail(f"Agent exited unexpectedly (code {agent_proc.returncode})")
                break

            # Print periodic stats
            metrics_text = check_metrics(metrics_port)
            if metrics_text:
                current_events = sum_metric_values(metrics_text, "edr_events_processed_total")
                current_time = time.time()
                dt = current_time - last_time
                if dt > 0:
                    rate = (current_events - last_events) / dt
                    queue_val = parse_metric_value(metrics_text, "edr_queue_depth") or 0
                    print(
                        f"  {CYAN}[LIVE]{RESET} "
                        f"events={current_events:.0f}  "
                        f"rate={rate:.1f}/s  "
                        f"queue={queue_val:.0f}  "
                        f"uptime={parse_metric_value(metrics_text, 'edr_agent_uptime_seconds') or 0:.0f}s"
                    )
                last_events = current_events
                last_time = current_time
    except KeyboardInterrupt:
        print()
        print_info("Shutting down agent...")

    # Graceful shutdown
    agent_proc.send_signal(signal.SIGTERM)
    try:
        agent_proc.wait(timeout=10)
        print_ok("Agent shut down cleanly")
    except subprocess.TimeoutExpired:
        print_warn("Agent didn't stop in 10s, sending SIGKILL")
        agent_proc.kill()
        agent_proc.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description="EDR Agent Pre-Flight Check — starts agent and verifies health")
    parser.add_argument(
        "--config",
        type=str,
        default=str(DEFAULT_CONFIG),
        help="Path to config YAML (default: tests/live/test_config.yaml)",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=DEFAULT_METRICS_PORT,
        help="Metrics/health port (default: 9100)",
    )
    args = parser.parse_args()

    run_preflight(Path(args.config), args.metrics_port)


if __name__ == "__main__":
    main()
