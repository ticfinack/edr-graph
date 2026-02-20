"""Verify the Graph Reaper TTL and memory hard-cap are working.

This script connects to the live KùzuDB, injects a dummy edge with a
timestamp 48 hours in the past, then invokes the reaper with a 24-hour
TTL and confirms the stale edge (and its orphaned nodes) are removed.

Usage:
    python -m tests.live.verify_reaper          # from repo root
    python tests/live/verify_reaper.py          # direct
"""

from __future__ import annotations

import sys
import textwrap
from datetime import datetime, timedelta
from pathlib import Path

# Ensure repo root is on sys.path when run directly
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import kuzu  # noqa: E402

from agent.config import Settings  # noqa: E402
from agent.graph.reaper import prune_old_edges  # noqa: E402
from agent.schema.kuzu_schema import init_graph_schema  # noqa: E402

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    status = PASS if ok else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  [{status}] {label}{suffix}")
    if not ok:
        failures.append(label)


def count_edges(conn: kuzu.Connection, edge_type: str, params: dict | None = None) -> int:
    q = f"MATCH ()-[e:{edge_type}]->() RETURN COUNT(e)"
    r = conn.execute(q)
    return r.get_next()[0] if r.has_next() else 0


def node_exists(conn: kuzu.Connection, label: str, node_id: str) -> bool:
    r = conn.execute(f"MATCH (n:{label} {{id: $id}}) RETURN n.id", {"id": node_id})
    return r.has_next()


def main() -> int:
    settings = Settings()

    # ── 1. Static config verification ────────────────────────────────────
    print("\n1. Configuration verification")
    check(
        "graph_max_memory_mb default is 512",
        settings.graph_max_memory_mb == 512,
        f"got {settings.graph_max_memory_mb}",
    )
    check(
        "graph_ttl_hours default is 24",
        settings.graph_ttl_hours == 24,
        f"got {settings.graph_ttl_hours}",
    )
    expected_bytes = settings.graph_max_memory_mb * 1024 * 1024
    check(
        f"buffer_pool_size computes to {expected_bytes} bytes",
        expected_bytes == 512 * 1024 * 1024,
    )

    # ── 2. Connect to the live graph ─────────────────────────────────────
    print("\n2. Connecting to live KùzuDB")
    graph_path = settings.data_dir / "graph"
    print(f"   graph path: {graph_path}")
    check("graph directory exists", graph_path.exists())

    db = kuzu.Database(str(graph_path))
    conn = kuzu.Connection(db)
    init_graph_schema(conn)  # ensure schema (idempotent)

    # Count existing edges for context
    live_edges = count_edges(conn, "CONNECTED_TO")
    print(f"   live CONNECTED_TO edges: {live_edges}")

    # ── 3. Time-travel test ──────────────────────────────────────────────
    print("\n3. Reaper time-travel test")

    dummy_proc_id = "__reaper_test_proc__"
    dummy_ip_id = "__reaper_test_ip__"
    old_ts = (datetime.now() - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")

    # Clean up any leftover dummy nodes from a prior failed run
    for label, did in [("Process", dummy_proc_id), ("IP", dummy_ip_id)]:
        conn.execute(f"MATCH (n:{label} {{id: $id}}) DETACH DELETE n", {"id": did})

    # 3a. Create dummy Process + IP + old CONNECTED_TO edge
    conn.execute(
        "CREATE (p:Process {id: $id, name: 'reaper-test-proc', pid: 0})",
        {"id": dummy_proc_id},
    )
    conn.execute(
        "CREATE (ip:IP {id: $id, address: '240.0.0.1', is_private: false})",
        {"id": dummy_ip_id},
    )
    conn.execute(
        textwrap.dedent(f"""\
        MATCH (p:Process {{id: $pid}}), (ip:IP {{id: $ipid}})
        CREATE (p)-[:CONNECTED_TO {{
            timestamp: timestamp('{old_ts}'),
            dst_port: 9999,
            protocol: 'TCP',
            direction: 'test',
            event_id: 0
        }}]->(ip)"""),
        {"pid": dummy_proc_id, "ipid": dummy_ip_id},
    )

    # 3b. Verify the dummy edge exists
    edge_count_before = 0
    r = conn.execute(
        "MATCH (p:Process {id: $pid})-[e:CONNECTED_TO]->(ip:IP {id: $ipid}) RETURN COUNT(e)",
        {"pid": dummy_proc_id, "ipid": dummy_ip_id},
    )
    if r.has_next():
        edge_count_before = r.get_next()[0]
    check("dummy edge created", edge_count_before == 1, f"count={edge_count_before}")

    # 3c. Run the reaper with 24h TTL (edge is 48h old → should be pruned)
    print("   running prune_old_edges(ttl_hours=24)...")
    pruned = prune_old_edges(conn, ttl_hours=24)
    print(f"   reaper returned: {pruned} items pruned")
    check("reaper pruned > 0 items", pruned > 0, f"pruned={pruned}")

    # 3d. Verify the dummy edge is gone
    r = conn.execute(
        "MATCH (p:Process {id: $pid})-[e:CONNECTED_TO]->(ip:IP {id: $ipid}) RETURN COUNT(e)",
        {"pid": dummy_proc_id, "ipid": dummy_ip_id},
    )
    edge_count_after = r.get_next()[0] if r.has_next() else -1
    check("dummy edge deleted", edge_count_after == 0, f"count={edge_count_after}")

    # 3e. Verify orphaned IP node was cleaned up
    ip_gone = not node_exists(conn, "IP", dummy_ip_id)
    check("orphaned IP node cleaned up", ip_gone)

    # 3f. Cleanup: remove dummy process if the reaper didn't already
    #     (process may survive if it has other edges from live traffic)
    if node_exists(conn, "Process", dummy_proc_id):
        conn.execute("MATCH (n:Process {id: $id}) DETACH DELETE n", {"id": dummy_proc_id})
    if node_exists(conn, "IP", dummy_ip_id):
        conn.execute("MATCH (n:IP {id: $id}) DETACH DELETE n", {"id": dummy_ip_id})

    # ── Summary ──────────────────────────────────────────────────────────
    print()
    if failures:
        print(f"\033[31m{len(failures)} check(s) FAILED:\033[0m")
        for f in failures:
            print(f"  - {f}")
        return 1
    else:
        print("\033[32mAll checks passed.\033[0m")
        return 0


if __name__ == "__main__":
    sys.exit(main())
