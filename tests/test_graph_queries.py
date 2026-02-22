"""Tests for Phase 2 Commit 2: Graph Query Helpers (2D).

Tests the graph traversal functions and attack chain building.
Uses a real in-memory Kuzu database for integration testing.
"""

import shutil
import tempfile

import kuzu

from agent.graph.queries import (
    build_attack_chain,
    get_domain_resolution_history,
    get_file_activity,
    get_process_chain,
    get_process_network_footprint,
    serialize_attack_chain,
)
from agent.schema.kuzu_schema import init_graph_schema


def _make_db():
    """Create a temporary Kuzu database with schema initialized."""
    tmp_dir = tempfile.mkdtemp()
    db_path = tmp_dir + "/test_db"
    db = kuzu.Database(db_path)
    conn = kuzu.Connection(db)
    init_graph_schema(conn)
    return db, conn, tmp_dir


def _ts(s: str) -> str:
    return f"timestamp('{s}')"


class TestGetProcessChain:
    def test_three_level_process_tree(self):
        """Build chain for a 3-level deep process tree."""
        db, conn, tmp_dir = _make_db()
        try:
            # Create user and processes
            conn.execute(
                "CREATE (u:User {id: 'root', name: 'root', uid: '0', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'host:1:1000', name: 'bash', pid: 1, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'host:2:1000', name: 'python', pid: 2, "
                "cmd_line: 'python malware.py', exe_path: '/usr/bin/python', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:01:00')}}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'host:3:1000', name: 'curl', pid: 3, "
                "cmd_line: 'curl http://evil.com', exe_path: '/usr/bin/curl', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )
            # Create SPAWNED edges
            conn.execute(
                "MATCH (u:User {id: 'root'}), (p:Process {id: 'host:1:1000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "activity_id: 1, event_id: 1}]->(p)"
            )
            conn.execute(
                "MATCH (u:User {id: 'root'}), (p:Process {id: 'host:2:1000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:01:00')}, "
                "activity_id: 1, event_id: 2}]->(p)"
            )

            chain = get_process_chain(conn, 1)
            assert len(chain) >= 1
            # Should contain the process
            proc_names = [p.get("name") for p in chain if "name" in p]
            assert "bash" in proc_names or "root" in proc_names
        finally:
            shutil.rmtree(tmp_dir)


class TestGetProcessNetworkFootprint:
    def test_process_with_dns_and_ip(self):
        """Process with both DNS queries and direct IP connections."""
        db, conn, tmp_dir = _make_db()
        try:
            # Create process
            conn.execute(
                "CREATE (p:Process {id: 'host:100:1000', name: 'curl', pid: 100, "
                "cmd_line: 'curl http://evil.com', exe_path: '/usr/bin/curl', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )

            # Create IP and CONNECTED_TO edge
            conn.execute(
                "CREATE (ip:IP {id: '1.2.3.4', address: '1.2.3.4', is_private: false, "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "MATCH (p:Process {id: 'host:100:1000'}), (ip:IP {id: '1.2.3.4'}) "
                f"CREATE (p)-[:CONNECTED_TO {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "dst_port: 443, protocol: 'TCP', direction: 'outbound', event_id: 1}]->(ip)"
            )

            # Create Domain, RESOLVED, and RESOLVES_TO edges
            conn.execute(
                "CREATE (d:Domain {id: 'evil.com', name: 'evil.com', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}, "
                "is_dga_candidate: false, tld: 'com'})"
            )
            conn.execute(
                "MATCH (p:Process {id: 'host:100:1000'}), (d:Domain {id: 'evil.com'}) "
                f"CREATE (p)-[:RESOLVED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 2}]->(d)"
            )
            conn.execute(
                "CREATE (ip2:IP {id: '5.6.7.8', address: '5.6.7.8', is_private: false, "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "MATCH (d:Domain {id: 'evil.com'}), (ip:IP {id: '5.6.7.8'}) "
                f"CREATE (d)-[:RESOLVES_TO {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 3}]->(ip)"
            )

            footprint = get_process_network_footprint(conn, 100)

            assert len(footprint["ips"]) == 1
            assert footprint["ips"][0]["address"] == "1.2.3.4"
            assert footprint["ips"][0]["port"] == 443

            assert len(footprint["domains"]) == 1
            assert footprint["domains"][0]["name"] == "evil.com"

            assert len(footprint["dns_chains"]) == 1
            assert "5.6.7.8" in footprint["dns_chains"][0]["resolved_to"]
        finally:
            shutil.rmtree(tmp_dir)


class TestBuildAttackChain:
    def test_complete_chain(self):
        """build_attack_chain produces a complete dict with all sections."""
        db, conn, tmp_dir = _make_db()
        try:
            # Create user
            conn.execute(
                "CREATE (u:User {id: 'attacker', name: 'attacker', uid: '1000', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            # Create process
            conn.execute(
                "CREATE (p:Process {id: 'host:500:1000', name: 'malware', pid: 500, "
                "cmd_line: './malware --steal', exe_path: '/tmp/malware', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )
            # SPAWNED edge
            conn.execute(
                "MATCH (u:User {id: 'attacker'}), (p:Process {id: 'host:500:1000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "activity_id: 1, event_id: 1}]->(p)"
            )
            # File
            conn.execute(
                "CREATE (f:File {id: '/etc/passwd', path: '/etc/passwd', hash_sha256: '', "
                f"size: 1024, first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "MATCH (p:Process {id: 'host:500:1000'}), (f:File {id: '/etc/passwd'}) "
                f"CREATE (p)-[:MODIFIED_FILE {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 2}]->(f)"
            )
            # Domain + DNS
            conn.execute(
                "CREATE (d:Domain {id: 'c2.evil.com', name: 'c2.evil.com', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}, "
                "is_dga_candidate: true, tld: 'com'})"
            )
            conn.execute(
                "MATCH (p:Process {id: 'host:500:1000'}), (d:Domain {id: 'c2.evil.com'}) "
                f"CREATE (p)-[:RESOLVED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 3}]->(d)"
            )

            chain = build_attack_chain(conn, 500)

            assert chain["target_process"]["name"] == "malware"
            assert chain["target_process"]["pid"] == 500
            assert chain["target_process"]["user"] == "attacker"
            assert len(chain["process_chain"]) > 0
            assert len(chain["network_footprint"]["domains"]) == 1
            assert len(chain["file_activity"]) == 1
            assert isinstance(chain["risk_indicators"], list)
        finally:
            shutil.rmtree(tmp_dir)

    def test_empty_activity_graceful(self):
        """build_attack_chain handles a process with zero activity."""
        db, conn, tmp_dir = _make_db()
        try:
            # Create a lonely process
            conn.execute(
                "CREATE (p:Process {id: 'host:999:1000', name: 'idle', pid: 999, "
                "cmd_line: '', exe_path: '', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )

            chain = build_attack_chain(conn, 999)

            assert chain["target_process"]["name"] == "idle"
            assert chain["network_footprint"]["domains"] == []
            assert chain["network_footprint"]["ips"] == []
            assert chain["file_activity"] == []
            assert chain["persistence_artifacts"] == []
            assert chain["risk_indicators"] == []
        finally:
            shutil.rmtree(tmp_dir)

    def test_nonexistent_process(self):
        """build_attack_chain still returns activity data for unknown pid.

        Even without a Process node in the graph, the chain queries for
        network, file, and persistence activity, and attempts psutil lookup.
        """
        db, conn, tmp_dir = _make_db()
        try:
            chain = build_attack_chain(conn, 99999)
            assert chain["target_process"]["pid"] == 99999
            assert chain["process_chain"] == []
            assert chain["file_activity"] == []
            assert chain["persistence_artifacts"] == []
        finally:
            shutil.rmtree(tmp_dir)


class TestSerializeAttackChain:
    def test_serialization_under_2000_tokens(self):
        """Serialized attack chain stays under 2000 tokens for moderate chain."""
        chain = {
            "target_process": {
                "pid": 500,
                "name": "malware",
                "command_line": "./malware --steal",
                "user": "attacker",
            },
            "process_chain": [
                {"type": "user", "id": "attacker", "name": "attacker"},
                {"name": "bash", "pid": 1},
                {"name": "malware", "pid": 500},
            ],
            "network_footprint": {
                "domains": [
                    {"name": "c2.evil.com", "is_dga_candidate": True},
                    {"name": "google.com", "is_dga_candidate": False},
                ],
                "ips": [{"address": "1.2.3.4", "port": 443, "protocol": "TCP"}],
                "dns_chains": [
                    {"domain": "c2.evil.com", "resolved_to": ["5.6.7.8"]},
                ],
            },
            "file_activity": [
                {"file_path": "/etc/passwd", "operation": "MODIFIED"},
                {"file_path": "/tmp/payload", "operation": "CREATED"},
            ],
            "persistence_artifacts": [
                {
                    "registry_path": r"HKLM\...\Run",
                    "value_data": r"C:\malware.exe",
                },
            ],
            "risk_indicators": ["DGA candidate (score: 0.85)", "Persistence: Run key"],
        }

        text = serialize_attack_chain(chain)
        # Rough token estimate: 4 chars per token
        estimated_tokens = len(text) / 4
        assert estimated_tokens < 2000
        assert "malware" in text
        assert "c2.evil.com" in text  # lgtm[py/incomplete-url-substring-sanitization] test data
        assert "[DGA?]" in text
        assert "Persistence" in text

    def test_empty_chain_serialization(self):
        """Empty chain serializes to minimal output."""
        chain = {
            "target_process": {},
            "process_chain": [],
            "network_footprint": {"domains": [], "ips": [], "dns_chains": []},
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
        }
        text = serialize_attack_chain(chain)
        assert text == ""


class TestGetDomainResolutionHistory:
    def test_resolution_history(self):
        """Get all IPs a domain resolved to."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (d:Domain {id: 'test.com', name: 'test.com', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}, "
                "is_dga_candidate: false, tld: 'com'})"
            )
            conn.execute(
                "CREATE (ip:IP {id: '1.1.1.1', address: '1.1.1.1', is_private: false, "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (ip2:IP {id: '2.2.2.2', address: '2.2.2.2', is_private: false, "
                f"first_seen: {_ts('2025-06-01 13:00:00')}, "
                f"last_seen: {_ts('2025-06-01 13:00:00')}}})"
            )
            conn.execute(
                "MATCH (d:Domain {id: 'test.com'}), (ip:IP {id: '1.1.1.1'}) "
                f"CREATE (d)-[:RESOLVES_TO {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 1}]->(ip)"
            )
            conn.execute(
                "MATCH (d:Domain {id: 'test.com'}), (ip:IP {id: '2.2.2.2'}) "
                f"CREATE (d)-[:RESOLVES_TO {{timestamp: {_ts('2025-06-01 13:00:00')}, "
                "event_id: 2}]->(ip)"
            )

            history = get_domain_resolution_history(conn, "test.com")
            assert len(history) == 2
            ips = {h["ip"] for h in history}
            assert ips == {"1.1.1.1", "2.2.2.2"}
        finally:
            shutil.rmtree(tmp_dir)


class TestGetFileActivity:
    def test_file_activity(self):
        """Get all processes that touched a file."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:10:1000', name: 'vim', pid: 10, "
                "cmd_line: 'vim /etc/hosts', exe_path: '/usr/bin/vim', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (f:File {id: '/etc/hosts', path: '/etc/hosts', hash_sha256: '', "
                f"size: 100, first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "MATCH (p:Process {id: 'host:10:1000'}), (f:File {id: '/etc/hosts'}) "
                f"CREATE (p)-[:MODIFIED_FILE {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "event_id: 1}]->(f)"
            )

            activity = get_file_activity(conn, "/etc/hosts")
            assert len(activity) == 1
            assert activity[0]["pid"] == 10
            assert activity[0]["process_name"] == "vim"
            assert activity[0]["operation"] == "MODIFIED"
        finally:
            shutil.rmtree(tmp_dir)
