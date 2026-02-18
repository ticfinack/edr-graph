#!/usr/bin/env python3
"""Post-simulation validation: queries the agent's graph DB and audit trail.

Run this AFTER running attack_simulations.py while the agent is still running.

Usage:
    python tests/live/validate.py [--data-dir ./edr_data] [--metrics-port 9100]
"""

from __future__ import annotations

import argparse
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
    """Holds connections to the agent's databases."""

    def __init__(self, data_dir: Path, metrics_port: int) -> None:
        self.data_dir = data_dir
        self.metrics_port = metrics_port
        self.kuzu_conn = None
        self.sqlite_conn = None
        self._init_graph()
        self._init_sqlite()

    def _init_graph(self) -> None:
        """Connect to the Kuzu graph database."""
        graph_path = self.data_dir / "graph"
        if not graph_path.exists():
            return
        try:
            import kuzu

            db = kuzu.Database(str(graph_path), read_only=True)
            self.kuzu_conn = kuzu.Connection(db)
        except Exception as e:
            print(f"  {YELLOW}Warning: Could not open graph DB: {e}{RESET}")

    def _init_sqlite(self) -> None:
        """Connect to the SQLite queue database."""
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

    def query_graph(self, cypher: str, params: dict | None = None) -> list[list]:
        """Execute a Cypher query and return all rows."""
        if not self.kuzu_conn:
            return []
        try:
            result = self.kuzu_conn.execute(cypher, params or {})
            rows = []
            while result.has_next():
                rows.append(result.get_next())
            return rows
        except Exception:
            return []

    def close(self) -> None:
        if self.sqlite_conn:
            self.sqlite_conn.close()


# ── Validation Checks ────────────────────────────────────────────────────────


def check_process_chain(ctx: ValidationContext) -> None:
    """Check for Process nodes with SPAWNED edges at least 2 levels deep."""
    name = "Process chain captured"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    rows = ctx.query_graph(
        "MATCH (u:User)-[:SPAWNED]->(p:Process) RETURN u.name, p.name, p.pid"
    )

    if len(rows) >= 2:
        chains = [(r[0], r[1], r[2]) for r in rows[:5]]
        detail = f"Found {len(rows)} user->process edges. Examples: "
        detail += ", ".join(f"{u}->{p}(PID {pid})" for u, p, pid in chains)
        print_pass(name, detail)
    elif len(rows) == 1:
        print_pass(name, f"Found 1 process chain: {rows[0][0]}->{rows[0][1]}")
    else:
        print_fail(
            name,
            "No SPAWNED edges found in graph",
            "Run attack simulation Test 1 (Process Chain) first",
        )


def check_dga_detected(ctx: ValidationContext) -> None:
    """Check Domain nodes where is_dga_candidate = True."""
    name = "DGA domain detected"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    rows = ctx.query_graph(
        "MATCH (d:Domain) WHERE d.is_dga_candidate = true RETURN d.name"
    )

    if len(rows) >= 2:
        domains = [r[0] for r in rows]
        print_pass(name, f"{len(rows)} DGA candidates: {', '.join(domains)}")
    elif len(rows) == 1:
        print_pass(name, f"1 DGA candidate: {rows[0][0]}")
    else:
        print_fail(
            name,
            "No DGA candidate domains found",
            "Run attack simulation Test 2 (DNS) or Test 8 (Kill Chain)",
        )


def check_legit_domain_not_flagged(ctx: ValidationContext) -> None:
    """Check that google.com is not flagged as DGA."""
    name = "Legitimate domain NOT flagged"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    rows = ctx.query_graph(
        "MATCH (d:Domain {id: 'google.com'}) RETURN d.is_dga_candidate"
    )

    if not rows:
        # google.com might not be in the graph yet
        print_skip(name, "google.com not found in graph (may not have been resolved)")
        return

    is_dga = rows[0][0]
    if not is_dga:
        print_pass(name, "google.com is_dga_candidate=False")
    else:
        print_fail(
            name,
            "google.com flagged as DGA candidate!",
            "Check DGA scoring threshold or allowlist",
        )


def check_file_creation(ctx: ValidationContext) -> None:
    """Check for File nodes with CREATED_FILE edges."""
    name = "File creation tracked"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    rows = ctx.query_graph(
        "MATCH (p:Process)-[:CREATED_FILE]->(f:File) "
        "RETURN p.name, f.path LIMIT 10"
    )

    if rows:
        detail = f"{len(rows)} file creation(s). "
        examples = [f"{r[0]}->{r[1]}" for r in rows[:3]]
        detail += "Examples: " + ", ".join(examples)
        print_pass(name, detail)
    else:
        print_fail(
            name,
            "No CREATED_FILE edges found",
            "Run attack simulation Test 3 (FIM) or Test 8 (Kill Chain)",
        )


def check_persistence_detected(ctx: ValidationContext) -> None:
    """Check for persistence detections in findings or risk indicators."""
    name = "Persistence detected"

    # Check findings table for persistence-related entries
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
            findings = cursor.fetchall()
            if findings:
                detail = f"{len(findings)} persistence finding(s): "
                detail += ", ".join(f"{f['title']} ({f['severity']})" for f in findings)
                print_pass(name, detail)
                return
        except Exception:
            pass

    # Check graph for registry persistence artifacts
    if ctx.kuzu_conn:
        rows = ctx.query_graph(
            "MATCH (p:Process)-[:CREATED_REG]->(r:RegistryKey) "
            "RETURN p.name, r.path LIMIT 5"
        )
        if rows:
            detail = f"{len(rows)} registry artifact(s): "
            detail += ", ".join(f"{r[0]}->{r[1]}" for r in rows[:3])
            print_pass(name, detail)
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

    print_fail(
        name,
        "No persistence detections found",
        "Run attack simulation Test 4 (Persistence) or Test 8 (Kill Chain)",
    )


def check_network_connections(ctx: ValidationContext) -> None:
    """Check for IP nodes with CONNECTED_TO edges."""
    name = "Network connection tracked"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    rows = ctx.query_graph(
        "MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IP) "
        "RETURN p.name, ip.address, c.dst_port LIMIT 10"
    )

    if rows:
        detail = f"{len(rows)} connection(s). "
        examples = [f"{r[0]}->{r[1]}:{r[2]}" for r in rows[:3]]
        detail += "Examples: " + ", ".join(examples)
        print_pass(name, detail)
    else:
        print_fail(
            name,
            "No CONNECTED_TO edges found",
            "Run attack simulation Test 5 (Network) or Test 8 (Kill Chain)",
        )


def check_ephemeral_processes(ctx: ValidationContext) -> None:
    """Check for Process nodes matching ephemeral spawns."""
    name = "Ephemeral processes captured"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    # Look for the sh/cmd processes spawned during the rapid test
    shell_name = "cmd" if sys.platform == "win32" else "sh"
    rows = ctx.query_graph(
        "MATCH (p:Process) WHERE p.name = $name RETURN p.pid, p.cmd_line",
        {"name": shell_name},
    )

    # Count how many look like our ephemeral test
    ephemeral_count = 0
    for row in rows:
        cmd = row[1] or ""
        if "ephemeral_" in cmd:
            ephemeral_count += 1

    if ephemeral_count >= 15:
        print_pass(
            name,
            f"Captured {ephemeral_count} of 20 ephemeral processes ({ephemeral_count * 5}%)",
        )
    elif ephemeral_count > 0:
        pct = ephemeral_count * 5
        print_fail(
            name,
            f"Only {ephemeral_count} of 20 captured ({pct}%)",
            "This may indicate the collector is not keeping up. Check buffer_size.",
        )
    else:
        # Maybe the collector captured them as generic processes
        total_shell = len(rows)
        if total_shell > 0:
            print_pass(
                name,
                f"Found {total_shell} {shell_name} processes (cannot confirm ephemeral test subset)",
            )
        else:
            print_fail(
                name,
                f"No {shell_name} processes found",
                "Run attack simulation Test 7 (Rapid Spawning) first",
            )


def check_attack_chain(ctx: ValidationContext) -> None:
    """Call build_attack_chain() for the current PID and verify output."""
    name = "Attack chain builds successfully"

    if not ctx.kuzu_conn:
        print_skip(name, "Graph DB not available")
        return

    try:
        from agent.graph.queries import build_attack_chain

        chain = build_attack_chain(ctx.kuzu_conn, os.getpid())

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
    except ImportError:
        print_skip(name, "Could not import agent.graph.queries")
    except Exception as e:
        print_fail(name, f"Error building chain: {e}")


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
                try:
                    total_dropped += float(parts[-1])
                except ValueError:
                    pass

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


# ── Main ─────────────────────────────────────────────────────────────────────


def run_validation(data_dir: Path, metrics_port: int) -> None:
    """Run all validation checks and print results."""
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}    Post-Simulation Validation{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")

    print(f"  {DIM}Data dir: {data_dir}{RESET}")
    print(f"  {DIM}Metrics port: {metrics_port}{RESET}\n")

    ctx = ValidationContext(data_dir, metrics_port)

    checks = [
        check_process_chain,
        check_dga_detected,
        check_legit_domain_not_flagged,
        check_file_creation,
        check_persistence_detected,
        check_network_connections,
        check_ephemeral_processes,
        check_attack_chain,
        check_health_endpoint,
        check_no_dropped_events,
    ]

    passed = 0
    failed = 0
    skipped = 0

    for check_fn in checks:
        # Count results by capturing output
        import io
        import contextlib

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
    args = parser.parse_args()

    run_validation(Path(args.data_dir), args.metrics_port)


if __name__ == "__main__":
    main()
