#!/usr/bin/env python3
"""Post-simulation validation: queries the agent via dashboard API.

Run this AFTER running attack_simulations.py while the agent is still running.
Uses the dashboard REST API (port 9200) so validation works while the agent is
running — no more Kuzu concurrent reader issues.

Usage:
    python tests/live/validate.py [--data-dir ./edr_data] [--metrics-port 9100] [--dashboard-port 9200]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

# Add project root to path for agent imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

DEFAULT_DATA_DIR = PROJECT_ROOT / "edr_data"
DEFAULT_METRICS_PORT = 9100
DEFAULT_DASHBOARD_PORT = 9200


def print_pass(name: str, detail: str) -> None:
    print(f"  {GREEN}[PASS]{RESET} {name}")
    if detail:
        print(f"         {DIM}{detail}{RESET}")


def print_fail(name: str, detail: str, hint: str = "") -> None:
    print(f"  {RED}[FAIL]{RESET} {name}")
    if detail:
        print(f"         {detail}")
    if hint:
        print(f"         {YELLOW}> {hint}{RESET}")


def print_skip(name: str, reason: str) -> None:
    print(f"  {YELLOW}[SKIP]{RESET} {name}")
    print(f"         {DIM}{reason}{RESET}")


class ValidationContext:
    """Holds connections to the agent's APIs and databases."""

    def __init__(self, data_dir: Path, metrics_port: int, dashboard_port: int) -> None:
        self.data_dir = data_dir
        self.metrics_port = metrics_port
        self.dashboard_port = dashboard_port
        self.dashboard_url = f"http://127.0.0.1:{dashboard_port}"
        self.sqlite_conn = None
        self._init_sqlite()

    def _init_sqlite(self) -> None:
        """Connect to the SQLite queue database (read-only, no locking issues)."""
        db_path = self.data_dir / "queue.db"
        if not db_path.exists():
            return
        try:
            self.sqlite_conn = sqlite3.connect(str(db_path))
            self.sqlite_conn.row_factory = sqlite3.Row
        except Exception as e:
            print(f"  {YELLOW}Warning: Could not open SQLite DB: {e}{RESET}")

    def fetch_metrics(self) -> str | None:
        try:
            with urlopen(
                f"http://127.0.0.1:{self.metrics_port}/metrics", timeout=5
            ) as resp:
                return resp.read().decode()
        except (URLError, OSError):
            return None

    def fetch_health(self) -> dict | None:
        try:
            with urlopen(
                f"http://127.0.0.1:{self.metrics_port}/health", timeout=5
            ) as resp:
                return json.loads(resp.read().decode())
        except (URLError, OSError, json.JSONDecodeError):
            return None

    def api_get(self, path: str) -> dict | None:
        """GET a dashboard API endpoint and return parsed JSON."""
        url = f"{self.dashboard_url}{path}"
        try:
            with urlopen(url, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except (URLError, OSError, json.JSONDecodeError):
            return None

    def close(self) -> None:
        if self.sqlite_conn:
            self.sqlite_conn.close()


# ── Validation Checks ────────────────────────────────────────────────────────


def check_dashboard_reachable(ctx: ValidationContext) -> None:
    """Verify the dashboard is reachable and serves HTML."""
    name = "Dashboard reachable"
    try:
        with urlopen(f"{ctx.dashboard_url}/", timeout=5) as resp:
            content = resp.read().decode()
            if "EDR" in content and "html" in content.lower():
                print_pass(name, f"GET / returns HTML on port {ctx.dashboard_port}")
            else:
                print_fail(name, "GET / returned content but doesn't look like dashboard HTML")
    except (URLError, OSError) as e:
        print_fail(name, f"Cannot reach dashboard on port {ctx.dashboard_port}: {e}")


def check_dashboard_api_status(ctx: ValidationContext) -> None:
    """Verify GET /api/status returns valid JSON."""
    name = "Dashboard API status"
    data = ctx.api_get("/api/status")
    if data and "agent_status" in data:
        status = data["agent_status"]
        uptime = data.get("uptime_seconds", 0)
        processed = data.get("events_processed", 0)
        eps = data.get("events_per_second", 0)
        queue = data.get("queue_depth", 0)
        print_pass(
            name,
            f"status={status}, uptime={uptime:.0f}s, events={processed}, "
            f"rate={eps}/s, queue={queue}",
        )
    else:
        print_fail(name, "GET /api/status failed or returned invalid JSON")


def check_process_chain(ctx: ValidationContext) -> None:
    """Check for Process nodes via dashboard graph stats API."""
    name = "Process chain captured"

    stats = ctx.api_get("/api/graph/stats")
    if not stats:
        print_skip(name, "Dashboard API /api/graph/stats not available")
        return

    process_count = stats.get("nodes", {}).get("Process", 0)
    spawned_count = stats.get("edges", {}).get("SPAWNED", 0)
    user_count = stats.get("nodes", {}).get("User", 0)

    if spawned_count >= 2:
        print_pass(
            name,
            f"{user_count} User nodes, {process_count} Process nodes, "
            f"{spawned_count} SPAWNED edges",
        )
    elif spawned_count == 1:
        print_pass(name, f"1 SPAWNED edge, {process_count} Process nodes")
    else:
        print_fail(
            name,
            f"No SPAWNED edges found ({process_count} Process nodes)",
            "Run attack simulation Test 1 (Process Chain) first",
        )


def check_dga_detected(ctx: ValidationContext) -> None:
    """Check for DGA detections via metrics."""
    name = "DGA domain detected"

    metrics_text = ctx.fetch_metrics()
    if not metrics_text:
        print_skip(name, "Cannot reach metrics endpoint")
        return

    dga_count = 0
    for line in metrics_text.splitlines():
        if line.startswith("edr_dga_detections_total "):
            parts = line.split()
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    dga_count = int(float(parts[-1]))

    # Also check graph for DGA domains
    stats = ctx.api_get("/api/graph/stats")
    domain_count = stats.get("nodes", {}).get("Domain", 0) if stats else 0

    if dga_count >= 2:
        print_pass(name, f"{dga_count} DGA detections, {domain_count} Domain nodes")
    elif dga_count == 1:
        print_pass(name, f"1 DGA detection, {domain_count} Domain nodes")
    else:
        print_fail(
            name,
            f"No DGA detections (metric=0, {domain_count} Domain nodes)",
            "Run attack simulation Test 2 (DNS) or Test 8 (Kill Chain)",
        )


def check_file_creation(ctx: ValidationContext) -> None:
    """Check for File nodes with CREATED_FILE edges via graph stats."""
    name = "File creation tracked"

    stats = ctx.api_get("/api/graph/stats")
    if not stats:
        print_skip(name, "Dashboard API not available")
        return

    file_count = stats.get("nodes", {}).get("File", 0)
    created_edges = stats.get("edges", {}).get("CREATED_FILE", 0)
    modified_edges = stats.get("edges", {}).get("MODIFIED_FILE", 0)

    if created_edges > 0:
        print_pass(
            name,
            f"{file_count} File nodes, {created_edges} CREATED_FILE, "
            f"{modified_edges} MODIFIED_FILE edges",
        )
    elif file_count > 0:
        print_pass(name, f"{file_count} File nodes (no CREATED_FILE edges)")
    else:
        print_fail(
            name,
            "No File nodes or CREATED_FILE edges found",
            "Run attack simulation Test 3 (FIM) or Test 8 (Kill Chain)",
        )


def check_persistence_detected(ctx: ValidationContext) -> None:
    """Check for persistence detections in findings."""
    name = "Persistence detected"

    # Check findings via API
    findings = ctx.api_get("/api/findings?limit=100")
    if findings and findings.get("findings"):
        for f in findings["findings"]:
            title = (f.get("title") or "").lower()
            desc = (f.get("description") or "").lower()
            if any(kw in title or kw in desc for kw in [
                "persist", "t1547", "t1543", "t1053", "launchagent", "launchdaemon"
            ]):
                print_pass(
                    name,
                    f"Finding: {f['title']} ({f['severity']})",
                )
                return

    # Check metrics for persistence detections
    metrics_text = ctx.fetch_metrics()
    if metrics_text:
        for line in metrics_text.splitlines():
            if line.startswith("edr_persistence_detections_total"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        val = float(parts[-1])
                        if val > 0:
                            print_pass(name, f"Persistence metric count: {val:.0f}")
                            return
                    except ValueError:
                        pass

    # Check SQLite directly as fallback
    if ctx.sqlite_conn:
        try:
            cursor = ctx.sqlite_conn.execute(
                "SELECT title, severity FROM findings "
                "WHERE lower(title) LIKE '%persist%' "
                "OR lower(description) LIKE '%t1547%' "
                "OR lower(description) LIKE '%t1543%' "
                "OR lower(description) LIKE '%t1053%' "
                "LIMIT 5"
            )
            rows = cursor.fetchall()
            if rows:
                detail = f"{len(rows)} persistence finding(s): "
                detail += ", ".join(f"{r['title']} ({r['severity']})" for r in rows)
                print_pass(name, detail)
                return
        except Exception:
            pass

    print_fail(
        name,
        "No persistence detections found",
        "Run attack simulation Test 4 (Persistence) or Test 8 (Kill Chain)",
    )


def check_network_connections(ctx: ValidationContext) -> None:
    """Check for IP nodes with CONNECTED_TO edges via graph stats."""
    name = "Network connection tracked"

    stats = ctx.api_get("/api/graph/stats")
    if not stats:
        print_skip(name, "Dashboard API not available")
        return

    ip_count = stats.get("nodes", {}).get("IP", 0)
    connected_edges = stats.get("edges", {}).get("CONNECTED_TO", 0)

    if connected_edges > 0:
        print_pass(name, f"{ip_count} IP nodes, {connected_edges} CONNECTED_TO edges")
    elif ip_count > 0:
        print_pass(name, f"{ip_count} IP nodes (no CONNECTED_TO edges)")
    else:
        print_fail(
            name,
            "No IP nodes or CONNECTED_TO edges found",
            "Run attack simulation Test 5 (Network) or Test 8 (Kill Chain)",
        )


def check_ephemeral_processes(ctx: ValidationContext) -> None:
    """Check process capture rate via metrics event source breakdown."""
    name = "Ephemeral processes captured"

    metrics_text = ctx.fetch_metrics()
    if not metrics_text:
        print_skip(name, "Cannot reach metrics endpoint")
        return

    # Count process events from metrics
    process_events = 0
    for line in metrics_text.splitlines():
        if line.startswith("edr_events_processed_total{") and "ProcessActivity" in line:
            parts = line.split()
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    process_events += int(float(parts[-1]))

    if process_events >= 20:
        print_pass(name, f"{process_events} ProcessActivity events captured")
    elif process_events > 0:
        print_pass(name, f"{process_events} ProcessActivity events (some ephemeral may be missed)")
    else:
        # Check graph for process nodes
        stats = ctx.api_get("/api/graph/stats")
        proc_count = stats.get("nodes", {}).get("Process", 0) if stats else 0
        if proc_count > 0:
            print_pass(name, f"{proc_count} Process nodes in graph (no ProcessActivity metrics)")
        else:
            print_fail(
                name,
                "No process events captured",
                "Run attack simulation Test 7 (Rapid Spawning) first",
            )


def check_attack_chain(ctx: ValidationContext) -> None:
    """Call the attack chain API for the current PID."""
    name = "Attack chain builds successfully"

    chain = ctx.api_get(f"/api/graph/attack-chain/{os.getpid()}")
    if not chain:
        print_fail(name, "Dashboard API /api/graph/attack-chain not available")
        return

    has_process = bool(chain.get("target_process"))
    has_chain = len(chain.get("process_chain", [])) > 0
    has_network = (
        len(chain.get("network_footprint", {}).get("domains", [])) > 0
        or len(chain.get("network_footprint", {}).get("ips", [])) > 0
    )
    has_files = len(chain.get("file_activity", [])) > 0
    has_risks = len(chain.get("risk_indicators", [])) > 0

    parts = []
    if has_process:
        parts.append("process")
    if has_chain:
        parts.append("chain")
    if has_network:
        parts.append("network")
    if has_files:
        parts.append("files")
    if has_risks:
        parts.append("risks")

    if parts:
        print_pass(name, f"Chain has: {', '.join(parts)}")
    else:
        print_fail(
            name,
            "Chain built but all sections empty for current PID",
            "Run attack simulations from within the same process or check PID tracking",
        )


def check_health_endpoint(ctx: ValidationContext) -> None:
    """Verify the health endpoint returns healthy."""
    name = "Metrics endpoint healthy"

    health = ctx.fetch_health()
    if health and health.get("status") == "healthy":
        uptime = health.get("uptime_seconds", 0)
        queue = health.get("queue_depth", 0)
        print_pass(name, f"status=healthy, uptime={uptime:.0f}s, queue_depth={queue}")
    elif health:
        print_fail(
            name,
            f"Health returned status={health.get('status', 'unknown')}",
        )
    else:
        print_fail(
            name,
            f"Cannot reach health endpoint on port {ctx.metrics_port}",
            "Is the agent still running?",
        )


def check_no_dropped_events(ctx: ValidationContext) -> None:
    """Verify events_dropped_total is 0."""
    name = "No dropped events"

    metrics_text = ctx.fetch_metrics()
    if not metrics_text:
        print_skip(name, "Cannot reach metrics endpoint")
        return

    total_dropped = 0.0
    for line in metrics_text.splitlines():
        if line.startswith("edr_events_dropped_total{"):
            parts = line.split()
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    total_dropped += float(parts[-1])

    if total_dropped == 0:
        print_pass(name, "events_dropped_total = 0")
    else:
        # Extract reasons
        reasons = []
        for line in metrics_text.splitlines():
            if line.startswith("edr_events_dropped_total{") and not line.startswith(
                "#"
            ):
                start = line.find('reason="')
                if start >= 0:
                    start += len('reason="')
                    end = line.find('"', start)
                    parts = line.split()
                    val = float(parts[-1]) if parts else 0
                    if val > 0:
                        reasons.append(f"{line[start:end]}={val:.0f}")

        print_fail(
            name,
            f"events_dropped_total = {total_dropped:.0f}",
            f"Reasons: {', '.join(reasons)}" if reasons else "Check agent logs",
        )


def check_llm_findings(ctx: ValidationContext) -> None:
    """Check LLM findings via dashboard API."""
    name = "LLM findings generated"

    findings = ctx.api_get("/api/findings?limit=50")
    if not findings:
        print_fail(name, "Dashboard API /api/findings not available")
        return

    total = findings.get("total", 0)
    finding_list = findings.get("findings", [])

    if total > 0:
        # Count by severity
        by_severity: dict[str, int] = {}
        for f in finding_list:
            sev = f.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        detail_parts = [f"{total} total"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_severity:
                detail_parts.append(f"{by_severity[sev]} {sev}")

        # Show first finding title
        if finding_list:
            detail_parts.append(f"Latest: {finding_list[0].get('title', '?')}")

        print_pass(name, ", ".join(detail_parts))
    else:
        print_fail(
            name,
            "No findings generated",
            "Wait for analyzer cycle (~60s) or check DEEPINFRA_API_KEY",
        )


def check_recent_events(ctx: ValidationContext) -> None:
    """Check recent events buffer via dashboard API."""
    name = "Recent events in dashboard"

    events = ctx.api_get("/api/events/recent?limit=100")
    if not events:
        print_fail(name, "Dashboard API /api/events/recent not available")
        return

    total = events.get("total", 0)
    event_list = events.get("events", [])

    if total > 0:
        # Count by source
        by_source: dict[str, int] = {}
        for e in event_list:
            src = e.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1

        source_str = ", ".join(f"{s}={c}" for s, c in sorted(by_source.items()))
        print_pass(name, f"{total} events in buffer. Sources: {source_str}")
    else:
        print_fail(
            name,
            "No events in recent events buffer",
            "Events should appear after processing starts",
        )


# ── Main ─────────────────────────────────────────────────────────────────────


def run_validation(data_dir: Path, metrics_port: int, dashboard_port: int) -> None:
    """Run all validation checks and print results."""
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}    Post-Simulation Validation{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")

    print(f"  {DIM}Data dir:       {data_dir}{RESET}")
    print(f"  {DIM}Metrics port:   {metrics_port}{RESET}")
    print(f"  {DIM}Dashboard port: {dashboard_port}{RESET}\n")

    ctx = ValidationContext(data_dir, metrics_port, dashboard_port)

    checks = [
        check_dashboard_reachable,
        check_dashboard_api_status,
        check_process_chain,
        check_dga_detected,
        check_file_creation,
        check_persistence_detected,
        check_network_connections,
        check_ephemeral_processes,
        check_attack_chain,
        check_health_endpoint,
        check_no_dropped_events,
        check_llm_findings,
        check_recent_events,
    ]

    passed = 0
    failed = 0
    skipped = 0

    for check_fn in checks:
        # Count results by capturing output
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check_fn(ctx)
        output = buf.getvalue()
        print(output, end="")

        if "[PASS]" in output:
            passed += 1
        elif "[FAIL]" in output:
            failed += 1
        elif "[SKIP]" in output:
            skipped += 1

    ctx.close()

    # Summary
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    total = passed + failed + skipped
    print(
        f"  {BOLD}Results:{RESET} "
        f"{GREEN}{passed} passed{RESET}, "
        f"{RED}{failed} failed{RESET}, "
        f"{YELLOW}{skipped} skipped{RESET} "
        f"/ {total} total"
    )
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")

    if failed > 0:
        print(
            f"  {YELLOW}Hint: Run attack_simulations.py while the agent is running,{RESET}"
        )
        print(
            f"  {YELLOW}wait ~60s for the analyzer cycle, then re-run this script.{RESET}"
        )
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post-simulation validation for EDR Agent"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=str(DEFAULT_DATA_DIR),
        help=f"Agent data directory (default: {DEFAULT_DATA_DIR})",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=DEFAULT_METRICS_PORT,
        help=f"Metrics/health port (default: {DEFAULT_METRICS_PORT})",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=DEFAULT_DASHBOARD_PORT,
        help=f"Dashboard API port (default: {DEFAULT_DASHBOARD_PORT})",
    )
    args = parser.parse_args()

    run_validation(Path(args.data_dir), args.metrics_port, args.dashboard_port)


if __name__ == "__main__":
    main()
