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


class TestAncestryFallbacks:
    """Tests for read-only ancestry fallbacks (ledger + OS)."""

    def test_ledger_fallback_extends_chain(self):
        """When parent_pid not in Kuzu, ledger fallback provides the ancestor."""
        from collections import namedtuple
        from unittest.mock import MagicMock, patch

        db, conn, tmp_dir = _make_db()
        try:
            # Create a child process whose parent (pid=100) is NOT in Kuzu
            conn.execute(
                "CREATE (p:Process {id: 'host:200:2000', name: 'malware', pid: 200, "
                "cmd_line: './malware', exe_path: '/tmp/malware', hostname: 'host', "
                "parent_pid: 100, "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )

            # Mock ledger returning a record for pid=100
            LedgerRow = namedtuple("LedgerRow", [
                "id", "ts", "event_type", "hostname", "pid", "parent_pid",
                "process_name", "username", "remote_ip", "remote_port",
                "ocsf_json", "entities_json", "ocsf", "entities",
            ])
            ledger_row = LedgerRow(
                id=1, ts=1717243200.0, event_type="ProcessActivity",
                hostname="host", pid=100, parent_pid=1,
                process_name="supervisord", username="root",
                remote_ip=None, remote_port=None,
                ocsf_json="{}", entities_json=None, ocsf=None, entities=None,
            )

            mock_writer = MagicMock()
            mock_writer._data_dir = "/tmp/fake"

            mock_reader = MagicMock()
            mock_reader.query_by_pid.return_value = [ledger_row]

            with patch("agent.graph.queries._query_process_from_ledger") as mock_fallback:
                mock_fallback.return_value = {
                    "id": "host:100:1717243200",
                    "name": "supervisord",
                    "pid": 100,
                    "cmd_line": "",
                    "exe_path": "",
                    "hostname": "host",
                    "parent_pid": 1,
                    "bundle_id": "",
                    "code_signed": None,
                    "signing_authority": "",
                    "_fallback": "ledger",
                }
                chain = get_process_chain(conn, 200)

            # Chain should have supervisord (from ledger) + malware
            proc_names = [p.get("name") for p in chain if p.get("name")]
            assert "supervisord" in proc_names
            assert "malware" in proc_names
            assert len(chain) >= 2
        finally:
            shutil.rmtree(tmp_dir)

    def test_os_fallback_extends_chain(self):
        """When parent not in Kuzu or ledger, OS fallback provides ancestor."""
        from unittest.mock import patch

        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:300:3000', name: 'child', pid: 300, "
                "cmd_line: './child', exe_path: '/tmp/child', hostname: 'host', "
                "parent_pid: 250, "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )

            with patch("agent.graph.queries._query_process_from_ledger", return_value=None), \
                 patch("agent.graph.queries._query_process_from_os") as mock_os:
                mock_os.return_value = {
                    "id": "host:250:1717243000",
                    "name": "containerd-shim",
                    "pid": 250,
                    "cmd_line": "/usr/bin/containerd-shim",
                    "exe_path": "/usr/bin/containerd-shim",
                    "hostname": "host",
                    "parent_pid": 0,
                    "bundle_id": "",
                    "code_signed": None,
                    "signing_authority": "",
                    "_fallback": "os",
                }
                chain = get_process_chain(conn, 300)

            proc_names = [p.get("name") for p in chain if p.get("name")]
            assert "containerd-shim" in proc_names
            assert "child" in proc_names
            assert len(chain) >= 2
        finally:
            shutil.rmtree(tmp_dir)

    def test_both_fallbacks_fail_chain_stops(self):
        """When both fallbacks return None, chain walk stops gracefully."""
        from unittest.mock import patch

        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:400:4000', name: 'orphan', pid: 400, "
                "cmd_line: './orphan', exe_path: '/tmp/orphan', hostname: 'host', "
                "parent_pid: 999, "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )

            with patch("agent.graph.queries._query_process_from_ledger", return_value=None), \
                 patch("agent.graph.queries._query_process_from_os", return_value=None):
                chain = get_process_chain(conn, 400)

            # Should still get the process itself, just no ancestors
            assert len(chain) == 1
            assert chain[0]["name"] == "orphan"
        finally:
            shutil.rmtree(tmp_dir)

    def test_multi_hop_fallback_chain(self):
        """Fallback chain walks multiple hops through ledger/OS ancestors."""
        from unittest.mock import patch

        db, conn, tmp_dir = _make_db()
        try:
            # Process in Kuzu with parent_pid=100 (not in Kuzu)
            conn.execute(
                "CREATE (p:Process {id: 'host:200:2000', name: 'unbound', pid: 200, "
                "cmd_line: '/usr/sbin/unbound', exe_path: '/usr/sbin/unbound', hostname: 'host', "
                "parent_pid: 100, "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )

            # Mock ledger: pid 100 = supervisord (ppid=50), pid 50 not in ledger
            def ledger_side_effect(pid, event_ts=None):
                if pid == 100:
                    return {
                        "id": "host:100:1717243200",
                        "name": "supervisord",
                        "pid": 100,
                        "cmd_line": "/usr/bin/supervisord",
                        "exe_path": "/usr/bin/supervisord",
                        "hostname": "host",
                        "parent_pid": 50,
                        "bundle_id": "",
                        "code_signed": None,
                        "signing_authority": "",
                        "_fallback": "ledger",
                    }
                return None

            # Mock OS: pid 50 = containerd-shim (ppid=1)
            def os_side_effect(pid, event_ts=None):
                if pid == 50:
                    return {
                        "id": "host:50:1717240000",
                        "name": "containerd-shim",
                        "pid": 50,
                        "cmd_line": "/usr/bin/containerd-shim",
                        "exe_path": "/usr/bin/containerd-shim",
                        "hostname": "host",
                        "parent_pid": 1,
                        "bundle_id": "",
                        "code_signed": None,
                        "signing_authority": "",
                        "_fallback": "os",
                    }
                return None

            with patch("agent.graph.queries._query_process_from_ledger", side_effect=ledger_side_effect), \
                 patch("agent.graph.queries._query_process_from_os", side_effect=os_side_effect):
                chain = get_process_chain(conn, 200)

            proc_names = [p.get("name") for p in chain if p.get("name")]
            assert proc_names == ["containerd-shim", "supervisord", "unbound"]
        finally:
            shutil.rmtree(tmp_dir)


    def test_user_fallback_from_os_metadata(self):
        """When no SPAWNED edge exists, user is resolved from OS fallback _username."""
        from unittest.mock import patch

        db, conn, tmp_dir = _make_db()
        try:
            # Daemon process in Kuzu — no SPAWNED edge exists
            conn.execute(
                "CREATE (p:Process {id: 'host:6434:9000', name: 'unbound', pid: 6434, "
                "cmd_line: '/usr/sbin/unbound', exe_path: '/usr/sbin/unbound', hostname: 'host', "
                "parent_pid: 1, "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )

            # psutil fallback should not be needed since the process is in Kuzu,
            # but no SPAWNED edge → _username from OS fallback on an ancestor
            # would be used.  Here parent_pid=1 so chain is just [unbound].
            # We mock psutil to provide the username fallback.
            mock_proc = type("P", (), {"username": lambda self: "unbound"})()
            with patch("psutil.Process", return_value=mock_proc):
                chain = get_process_chain(conn, 6434)

            # First entry should be the user
            assert chain[0].get("type") == "user"
            assert chain[0].get("name") == "unbound"
            # Second entry should be the process
            assert chain[1].get("name") == "unbound"
            assert chain[1].get("pid") == 6434
        finally:
            shutil.rmtree(tmp_dir)

    def test_user_fallback_from_os_fallback_dict(self):
        """When ancestor comes from OS fallback with _username, user is inserted."""
        from unittest.mock import patch

        db, conn, tmp_dir = _make_db()
        try:
            # Process in Kuzu with parent_pid=100 (not in Kuzu)
            conn.execute(
                "CREATE (p:Process {id: 'host:200:2000', name: 'worker', pid: 200, "
                "cmd_line: '/usr/bin/worker', exe_path: '/usr/bin/worker', hostname: 'host', "
                "parent_pid: 100, "
                f"start_time: {_ts('2025-06-01 12:02:00')}}})"
            )

            # OS fallback returns parent with _username
            def os_side_effect(pid, event_ts=None):
                if pid == 100:
                    return {
                        "id": "host:100:1000",
                        "name": "supervisord",
                        "pid": 100,
                        "cmd_line": "/usr/bin/supervisord",
                        "exe_path": "/usr/bin/supervisord",
                        "hostname": "host",
                        "parent_pid": 1,
                        "bundle_id": "",
                        "code_signed": None,
                        "signing_authority": "",
                        "_fallback": "os",
                        "_username": "root",
                        "_uid": 0,
                    }
                return None

            with patch("agent.graph.queries._query_process_from_ledger", return_value=None), \
                 patch("agent.graph.queries._query_process_from_os", side_effect=os_side_effect):
                chain = get_process_chain(conn, 200)

            assert chain[0].get("type") == "user"
            assert chain[0].get("name") == "root"
            assert chain[1].get("name") == "supervisord"
            assert chain[2].get("name") == "worker"
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
