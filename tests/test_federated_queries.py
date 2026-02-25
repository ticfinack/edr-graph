"""Tests for agent-side federated query handlers."""

from __future__ import annotations

import kuzu
import pytest

from agent.graph import connection as kuzu_conn
from agent.graph.federated_queries import execute_query, lateral_source_trace, lateral_victim_trace


@pytest.fixture
def kuzu_db(tmp_path):
    """Create a temporary Kuzu database with the required schema."""
    db = kuzu.Database(str(tmp_path / "test_kuzu"))
    kuzu_conn.init(db)
    conn = kuzu.Connection(db)
    # Minimal schema for testing
    conn.execute(
        "CREATE NODE TABLE IF NOT EXISTS Process("
        "id STRING, name STRING, pid INT64, cmd_line STRING, "
        "hostname STRING, parent_pid INT64, PRIMARY KEY (id))"
    )
    conn.execute(
        "CREATE NODE TABLE IF NOT EXISTS IP("
        "id STRING, address STRING, PRIMARY KEY (id))"
    )
    conn.execute(
        "CREATE NODE TABLE IF NOT EXISTS User("
        "id STRING, name STRING, PRIMARY KEY (id))"
    )
    conn.execute(
        "CREATE REL TABLE IF NOT EXISTS CONNECTED_TO("
        "FROM Process TO IP, timestamp TIMESTAMP, dst_port INT64, "
        "protocol STRING, direction STRING, event_id INT64)"
    )
    conn.execute(
        "CREATE REL TABLE IF NOT EXISTS SPAWNED("
        "FROM User TO Process, timestamp TIMESTAMP, "
        "activity_id INT64, event_id INT64)"
    )
    conn.close()
    yield db
    # Reset global state so later tests don't see a stale _db
    kuzu_conn.init.__wrapped__(None) if hasattr(kuzu_conn.init, '__wrapped__') else None
    kuzu_conn._db = None
    kuzu_conn._reader_conn = None
    kuzu_conn._writer_conn = None
    kuzu_conn._locked_reader = None


class TestLateralVictimTrace:
    def test_finds_inbound_ssh(self, kuzu_db):
        """Inbound CONNECTED_TO edge from sshd to source IP is returned."""
        conn = kuzu.Connection(kuzu_db)
        # Create sshd process
        conn.execute(
            "CREATE (p:Process {id: 'mp1001:800:1700000000', name: 'sshd', "
            "pid: 800, cmd_line: '/usr/sbin/sshd -D', hostname: 'mp1001', parent_pid: 1})"
        )
        # Create source IP
        conn.execute("CREATE (ip:IP {id: '192.168.1.189', address: '192.168.1.189'})")
        # Create user
        conn.execute("CREATE (u:User {id: 'thomas', name: 'thomas'})")
        # Create inbound CONNECTED_TO edge
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:800:1700000000'}), (ip:IP {id: '192.168.1.189'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 1}]->(ip)"
        )
        # Create SPAWNED edge
        conn.execute(
            "MATCH (u:User {id: 'thomas'}), (p:Process {id: 'mp1001:800:1700000000'}) "
            "CREATE (u)-[:SPAWNED {event_id: 1}]->(p)"
        )
        conn.close()

        result = lateral_victim_trace(kuzu_db, {"victim_ips": ["192.168.1.189"]})

        assert result["status"] == "ok"
        assert len(result["records"]) == 1
        rec = result["records"][0]
        assert rec["process_name"] == "sshd"
        assert rec["pid"] == 800
        assert rec["from_ip"] == "192.168.1.189"
        assert rec["dst_port"] == 22
        assert rec["username"] == "thomas"

    def test_no_match_returns_empty(self, kuzu_db):
        """Empty graph returns ok with no records."""
        result = lateral_victim_trace(kuzu_db, {"victim_ips": ["10.0.0.99"]})

        assert result["status"] == "ok"
        assert result["records"] == []

    def test_filters_outbound_connections(self, kuzu_db):
        """Outbound connections (direction != 'inbound') are not returned."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p:Process {id: 'mp1001:900:1700000000', name: 'curl', "
            "pid: 900, cmd_line: 'curl https://example.com', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '93.184.216.34', address: '93.184.216.34'})")
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:900:1700000000'}), (ip:IP {id: '93.184.216.34'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 443, "
            "protocol: 'tcp', event_id: 2}]->(ip)"
        )
        conn.close()

        result = lateral_victim_trace(kuzu_db, {"victim_ips": ["93.184.216.34"]})

        assert result["status"] == "ok"
        assert result["records"] == []

    def test_filters_by_target_port(self, kuzu_db):
        """target_port filters to only matching dst_port edges."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p1:Process {id: 'mp1001:800:1700000000', name: 'sshd', "
            "pid: 800, cmd_line: '/usr/sbin/sshd', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute(
            "CREATE (p2:Process {id: 'mp1001:900:1700000001', name: 'httpd', "
            "pid: 900, cmd_line: '/usr/sbin/httpd', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '192.168.1.189', address: '192.168.1.189'})")
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:800:1700000000'}), (ip:IP {id: '192.168.1.189'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 10}]->(ip)"
        )
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:900:1700000001'}), (ip:IP {id: '192.168.1.189'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 80, "
            "protocol: 'tcp', event_id: 11}]->(ip)"
        )
        conn.close()

        result = lateral_victim_trace(kuzu_db, {"victim_ips": ["192.168.1.189"], "target_port": 22})

        assert result["status"] == "ok"
        assert len(result["records"]) == 1
        assert result["records"][0]["process_name"] == "sshd"
        assert result["records"][0]["dst_port"] == 22

    def test_no_port_returns_all(self, kuzu_db):
        """No target_port returns all matching inbound connections (backward compat)."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p1:Process {id: 'mp1001:801:1700000000', name: 'sshd', "
            "pid: 801, cmd_line: '/usr/sbin/sshd', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute(
            "CREATE (p2:Process {id: 'mp1001:901:1700000001', name: 'httpd', "
            "pid: 901, cmd_line: '/usr/sbin/httpd', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '10.0.0.50', address: '10.0.0.50'})")
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:801:1700000000'}), (ip:IP {id: '10.0.0.50'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 20}]->(ip)"
        )
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:901:1700000001'}), (ip:IP {id: '10.0.0.50'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 80, "
            "protocol: 'tcp', event_id: 21}]->(ip)"
        )
        conn.close()

        result = lateral_victim_trace(kuzu_db, {"victim_ips": ["10.0.0.50"]})

        assert result["status"] == "ok"
        assert len(result["records"]) == 2


class TestLateralSourceTrace:
    def test_finds_outbound_ssh(self, kuzu_db):
        """Outbound CONNECTED_TO edge from ssh client to destination IP is returned."""
        conn = kuzu.Connection(kuzu_db)
        # Create ssh client process
        conn.execute(
            "CREATE (p:Process {id: 'ticbook:500:1700000000', name: 'ssh', "
            "pid: 500, cmd_line: 'ssh thomas@10.199.0.5', hostname: 'ticbook', parent_pid: 100})"
        )
        # Create destination IP (victim)
        conn.execute("CREATE (ip:IP {id: '10.199.0.5', address: '10.199.0.5'})")
        # Create user
        conn.execute("CREATE (u:User {id: 'thomas', name: 'thomas'})")
        # Create outbound CONNECTED_TO edge
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:500:1700000000'}), (ip:IP {id: '10.199.0.5'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 1}]->(ip)"
        )
        # Create SPAWNED edge
        conn.execute(
            "MATCH (u:User {id: 'thomas'}), (p:Process {id: 'ticbook:500:1700000000'}) "
            "CREATE (u)-[:SPAWNED {event_id: 1}]->(p)"
        )
        conn.close()

        result = lateral_source_trace(kuzu_db, {"dst_ips": ["10.199.0.5"]})

        assert result["status"] == "ok"
        assert len(result["records"]) == 1
        rec = result["records"][0]
        assert rec["process_name"] == "ssh"
        assert rec["pid"] == 500
        assert rec["from_ip"] == "10.199.0.5"
        assert rec["dst_port"] == 22
        assert rec["username"] == "thomas"

    def test_no_match_returns_empty(self, kuzu_db):
        """Empty graph returns ok with no records."""
        result = lateral_source_trace(kuzu_db, {"dst_ips": ["10.0.0.99"]})

        assert result["status"] == "ok"
        assert result["records"] == []

    def test_filters_inbound_connections(self, kuzu_db):
        """Inbound connections (direction != 'outbound') are not returned."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p:Process {id: 'mp1001:800:1700000000', name: 'sshd', "
            "pid: 800, cmd_line: '/usr/sbin/sshd', hostname: 'mp1001', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '192.168.1.189', address: '192.168.1.189'})")
        conn.execute(
            "MATCH (p:Process {id: 'mp1001:800:1700000000'}), (ip:IP {id: '192.168.1.189'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'inbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 2}]->(ip)"
        )
        conn.close()

        result = lateral_source_trace(kuzu_db, {"dst_ips": ["192.168.1.189"]})

        assert result["status"] == "ok"
        assert result["records"] == []

    def test_multiple_dst_ips(self, kuzu_db):
        """Multiple destination IPs are searched and results aggregated."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p:Process {id: 'ticbook:500:1700000000', name: 'ssh', "
            "pid: 500, cmd_line: 'ssh root@10.0.0.1', hostname: 'ticbook', parent_pid: 1})"
        )
        conn.execute("CREATE (ip1:IP {id: '10.0.0.1', address: '10.0.0.1'})")
        conn.execute("CREATE (ip2:IP {id: '10.0.0.2', address: '10.0.0.2'})")
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:500:1700000000'}), (ip:IP {id: '10.0.0.1'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 1}]->(ip)"
        )
        conn.close()

        result = lateral_source_trace(kuzu_db, {"dst_ips": ["10.0.0.1", "10.0.0.2"]})

        assert result["status"] == "ok"
        assert len(result["records"]) == 1
        assert result["records"][0]["from_ip"] == "10.0.0.1"

    def test_filters_by_target_port(self, kuzu_db):
        """target_port filters to only matching dst_port edges."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p1:Process {id: 'ticbook:501:1700000000', name: 'ssh', "
            "pid: 501, cmd_line: 'ssh thomas@10.199.0.5', hostname: 'ticbook', parent_pid: 1})"
        )
        conn.execute(
            "CREATE (p2:Process {id: 'ticbook:502:1700000001', name: 'curl', "
            "pid: 502, cmd_line: 'curl https://10.199.0.5', hostname: 'ticbook', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '10.199.0.5', address: '10.199.0.5'})")
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:501:1700000000'}), (ip:IP {id: '10.199.0.5'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 30}]->(ip)"
        )
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:502:1700000001'}), (ip:IP {id: '10.199.0.5'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 443, "
            "protocol: 'tcp', event_id: 31}]->(ip)"
        )
        conn.close()

        result = lateral_source_trace(kuzu_db, {"dst_ips": ["10.199.0.5"], "target_port": 22})

        assert result["status"] == "ok"
        assert len(result["records"]) == 1
        assert result["records"][0]["process_name"] == "ssh"
        assert result["records"][0]["dst_port"] == 22

    def test_no_port_returns_all(self, kuzu_db):
        """No target_port returns all matching outbound connections (backward compat)."""
        conn = kuzu.Connection(kuzu_db)
        conn.execute(
            "CREATE (p1:Process {id: 'ticbook:503:1700000000', name: 'ssh', "
            "pid: 503, cmd_line: 'ssh root@10.0.0.60', hostname: 'ticbook', parent_pid: 1})"
        )
        conn.execute(
            "CREATE (p2:Process {id: 'ticbook:504:1700000001', name: 'curl', "
            "pid: 504, cmd_line: 'curl http://10.0.0.60', hostname: 'ticbook', parent_pid: 1})"
        )
        conn.execute("CREATE (ip:IP {id: '10.0.0.60', address: '10.0.0.60'})")
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:503:1700000000'}), (ip:IP {id: '10.0.0.60'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 22, "
            "protocol: 'tcp', event_id: 40}]->(ip)"
        )
        conn.execute(
            "MATCH (p:Process {id: 'ticbook:504:1700000001'}), (ip:IP {id: '10.0.0.60'}) "
            "CREATE (p)-[:CONNECTED_TO {direction: 'outbound', dst_port: 80, "
            "protocol: 'tcp', event_id: 41}]->(ip)"
        )
        conn.close()

        result = lateral_source_trace(kuzu_db, {"dst_ips": ["10.0.0.60"]})

        assert result["status"] == "ok"
        assert len(result["records"]) == 2


class TestExecuteQuery:
    def test_unknown_type_returns_error(self, kuzu_db):
        """Unknown query_type returns an error dict."""
        result = execute_query(kuzu_db, "nonexistent_query", {})
        assert "error" in result
        assert "unknown query_type" in result["error"]

    def test_dispatches_lateral_victim_trace(self, kuzu_db):
        """execute_query dispatches to lateral_victim_trace handler."""
        result = execute_query(kuzu_db, "lateral_victim_trace", {"victim_ips": []})
        assert result["status"] == "ok"
        assert result["records"] == []

    def test_dispatches_lateral_source_trace(self, kuzu_db):
        """execute_query dispatches to lateral_source_trace handler."""
        result = execute_query(kuzu_db, "lateral_source_trace", {"dst_ips": []})
        assert result["status"] == "ok"
        assert result["records"] == []
