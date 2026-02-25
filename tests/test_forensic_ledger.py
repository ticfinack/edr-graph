"""Tests for the forensic ledger: writer, reader, serializer."""

from __future__ import annotations

import time
from datetime import datetime

import pytest

from agent.ledger.reader import LedgerReader
from agent.ledger.serializer import (
    deserialize_entities,
    deserialize_ocsf,
    serialize_entities,
    serialize_ocsf,
)
from agent.ledger.writer import LedgerWriter
from agent.processor.entity_extractor import ExtractedEntities
from agent.schema.graph_types import (
    DomainNode,
    FileNode,
    IpNode,
    ProcessNode,
    RegistryKeyNode,
    UserNode,
)
from agent.schema.ocsf_types import (
    Authentication,
    DeviceInfo,
    DnsActivity,
    FileActivity,
    NetworkActivity,
    NetworkEndpoint,
    ProcessActivity,
    ProcessInfo,
    RegistryActivity,
    UserInfo,
)


# ── OCSF Event Factories ──


def _now():
    return datetime.now()


def _make_process_activity():
    return ProcessActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=1234, name="bash", cmd_line="bash -l", parent_pid=1),
        device=DeviceInfo(hostname="test-host"),
    )


def _make_network_activity():
    return NetworkActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=5678, name="curl"),
        dst_endpoint=NetworkEndpoint(ip="93.184.216.34", port=443),
        device=DeviceInfo(hostname="test-host"),
    )


def _make_authentication():
    return Authentication(
        activity_id=1,
        status_id=1,
        time=_now(),
        user=UserInfo(name="root"),
        src_endpoint=NetworkEndpoint(ip="10.0.0.5"),
        device=DeviceInfo(hostname="test-host"),
    )


def _make_dns_activity():
    return DnsActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=9999, name="dig"),
        query_domain="example.com",
        resolved_ips=["93.184.216.34"],
        device=DeviceInfo(hostname="test-host"),
    )


def _make_file_activity():
    return FileActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=2222, name="vim"),
        file_path="/tmp/test.txt",
        device=DeviceInfo(hostname="test-host"),
    )


def _make_registry_activity():
    return RegistryActivity(
        activity_id=1,
        time=_now(),
        process=ProcessInfo(pid=3333, name="regedit"),
        reg_path="HKLM\\Software\\Test",
        reg_value_name="key1",
        reg_value_data="val1",
        device=DeviceInfo(hostname="test-host"),
    )


def _make_entities_for(ocsf):
    """Build minimal ExtractedEntities matching an OCSF event."""
    entities = ExtractedEntities()
    now = _now()
    if isinstance(ocsf, ProcessActivity):
        entities.processes.append(ProcessNode(
            id="test-host:1234:0", name="bash", pid=1234,
            hostname="test-host", start_time=now, parent_pid=1,
        ))
        entities.users.append(UserNode(id="root", name="root", first_seen=now, last_seen=now))
    elif isinstance(ocsf, NetworkActivity):
        entities.processes.append(ProcessNode(
            id="test-host:5678:0", name="curl", pid=5678,
            hostname="test-host", start_time=now,
        ))
        entities.ips.append(IpNode(
            id="93.184.216.34", address="93.184.216.34",
            is_private=False, first_seen=now, last_seen=now,
        ))
        entities.connected_edges.append({
            "process_id": "test-host:5678:0", "ip_id": "93.184.216.34",
            "timestamp": now, "dst_port": 443, "protocol": "TCP",
            "direction": "outbound", "event_id": 1,
        })
    elif isinstance(ocsf, Authentication):
        entities.users.append(UserNode(id="root", name="root", first_seen=now, last_seen=now))
        entities.ips.append(IpNode(
            id="10.0.0.5", address="10.0.0.5",
            is_private=True, first_seen=now, last_seen=now,
        ))
    elif isinstance(ocsf, DnsActivity):
        entities.processes.append(ProcessNode(
            id="test-host:9999:0", name="dig", pid=9999,
            hostname="test-host", start_time=now,
        ))
        entities.domains.append(DomainNode(
            id="example.com", name="example.com",
            first_seen=now, last_seen=now,
        ))
    elif isinstance(ocsf, FileActivity):
        entities.processes.append(ProcessNode(
            id="test-host:2222:0", name="vim", pid=2222,
            hostname="test-host", start_time=now,
        ))
        entities.files.append(FileNode(
            id="/tmp/test.txt", path="/tmp/test.txt",
            first_seen=now, last_seen=now,
        ))
    elif isinstance(ocsf, RegistryActivity):
        entities.processes.append(ProcessNode(
            id="test-host:3333:0", name="regedit", pid=3333,
            hostname="test-host", start_time=now,
        ))
        entities.registry_keys.append(RegistryKeyNode(
            id="HKLM\\Software\\Test\\key1",
            path="HKLM\\Software\\Test",
            value_name="key1", value_data="val1",
            first_seen=now, last_seen=now,
        ))
    return entities


# ── Serializer Tests ──


class TestOcsfSerialization:
    """Test OCSF round-trip serialization for all 6 event types."""

    @pytest.mark.parametrize("factory", [
        _make_process_activity,
        _make_network_activity,
        _make_authentication,
        _make_dns_activity,
        _make_file_activity,
        _make_registry_activity,
    ])
    def test_ocsf_roundtrip(self, factory):
        """Serialize and deserialize preserves the OCSF event."""
        original = factory()
        json_str = serialize_ocsf(original)
        restored = deserialize_ocsf(json_str)
        assert type(restored) is type(original)
        assert restored.class_uid == original.class_uid

    def test_ocsf_unknown_class_uid_raises(self):
        """deserialize_ocsf raises ValueError for unknown class_uid."""
        with pytest.raises(ValueError, match="Unknown class_uid"):
            deserialize_ocsf('{"class_uid": 99999}')

    def test_process_activity_fields_survive(self):
        """ProcessActivity fields survive serialization."""
        event = _make_process_activity()
        restored = deserialize_ocsf(serialize_ocsf(event))
        assert restored.process.pid == 1234
        assert restored.process.name == "bash"
        assert restored.process.cmd_line == "bash -l"
        assert restored.device.hostname == "test-host"

    def test_network_activity_fields_survive(self):
        """NetworkActivity fields survive serialization."""
        event = _make_network_activity()
        restored = deserialize_ocsf(serialize_ocsf(event))
        assert restored.dst_endpoint.ip == "93.184.216.34"
        assert restored.dst_endpoint.port == 443
        assert restored.process.name == "curl"

    def test_authentication_fields_survive(self):
        """Authentication fields survive serialization."""
        event = _make_authentication()
        restored = deserialize_ocsf(serialize_ocsf(event))
        assert restored.user.name == "root"
        assert restored.status_id == 1
        assert restored.src_endpoint.ip == "10.0.0.5"


class TestEntitiesSerialization:
    """Test ExtractedEntities round-trip serialization."""

    def test_entities_roundtrip_process(self):
        """ProcessNode + UserNode + edges survive serialization."""
        ocsf = _make_process_activity()
        entities = _make_entities_for(ocsf)
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)

        assert len(restored.processes) == 1
        assert restored.processes[0].pid == 1234
        assert restored.processes[0].name == "bash"
        assert len(restored.users) == 1
        assert restored.users[0].name == "root"

    def test_entities_roundtrip_network(self):
        """IpNode + connected_edges survive serialization."""
        ocsf = _make_network_activity()
        entities = _make_entities_for(ocsf)
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)

        assert len(restored.ips) == 1
        assert restored.ips[0].address == "93.184.216.34"
        assert len(restored.connected_edges) == 1
        assert restored.connected_edges[0]["dst_port"] == 443

    def test_entities_roundtrip_domain(self):
        """DomainNode survives serialization."""
        ocsf = _make_dns_activity()
        entities = _make_entities_for(ocsf)
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)

        assert len(restored.domains) == 1
        assert restored.domains[0].name == "example.com"

    def test_entities_roundtrip_file(self):
        """FileNode survives serialization."""
        ocsf = _make_file_activity()
        entities = _make_entities_for(ocsf)
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)

        assert len(restored.files) == 1
        assert restored.files[0].path == "/tmp/test.txt"

    def test_entities_roundtrip_registry(self):
        """RegistryKeyNode survives serialization."""
        ocsf = _make_registry_activity()
        entities = _make_entities_for(ocsf)
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)

        assert len(restored.registry_keys) == 1
        assert restored.registry_keys[0].value_name == "key1"

    def test_empty_entities(self):
        """Empty ExtractedEntities round-trips cleanly."""
        entities = ExtractedEntities()
        json_str = serialize_entities(entities)
        restored = deserialize_entities(json_str)
        assert len(restored.processes) == 0
        assert len(restored.ips) == 0


# ── Writer Tests ──


class TestLedgerWriter:
    def test_record_and_flush(self, tmp_path):
        """Writer enqueues, background thread flushes to SQLite."""
        writer = LedgerWriter(tmp_path, ttl_hours=24)
        try:
            ocsf = _make_process_activity()
            entities = _make_entities_for(ocsf)
            writer.record(ocsf, entities, event_id=1)
            time.sleep(1.5)

            # Verify via direct SQLite read
            import sqlite3
            conn = sqlite3.connect(str(writer.db_path))
            row = conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()
            conn.close()
            assert row[0] == 1
        finally:
            writer.stop()

    def test_record_all_event_types(self, tmp_path):
        """All 6 OCSF event types are recorded."""
        writer = LedgerWriter(tmp_path)
        try:
            factories = [
                _make_process_activity,
                _make_network_activity,
                _make_authentication,
                _make_dns_activity,
                _make_file_activity,
                _make_registry_activity,
            ]
            for i, factory in enumerate(factories):
                ocsf = factory()
                entities = _make_entities_for(ocsf)
                writer.record(ocsf, entities, event_id=i)
            time.sleep(1.5)

            import sqlite3
            conn = sqlite3.connect(str(writer.db_path))
            row = conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()
            types = conn.execute(
                "SELECT DISTINCT event_type FROM forensic_ledger ORDER BY event_type"
            ).fetchall()
            conn.close()
            assert row[0] == 6
            type_names = {t[0] for t in types}
            assert type_names == {
                "ProcessActivity", "NetworkActivity", "Authentication",
                "DnsActivity", "FileActivity", "RegistryActivity",
            }
        finally:
            writer.stop()

    def test_denormalized_columns(self, tmp_path):
        """Denormalized columns (pid, hostname, etc.) are populated."""
        writer = LedgerWriter(tmp_path)
        try:
            ocsf = _make_network_activity()
            entities = _make_entities_for(ocsf)
            writer.record(ocsf, entities, event_id=1)
            time.sleep(1.5)

            import sqlite3
            conn = sqlite3.connect(str(writer.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM forensic_ledger").fetchone()
            conn.close()

            assert row["pid"] == 5678
            assert row["hostname"] == "test-host"
            assert row["process_name"] == "curl"
            assert row["remote_ip"] == "93.184.216.34"
            assert row["remote_port"] == 443
            assert row["event_type"] == "NetworkActivity"
        finally:
            writer.stop()

    def test_stop_flushes_remaining(self, tmp_path):
        """stop() flushes queued events before returning."""
        writer = LedgerWriter(tmp_path)
        ocsf = _make_process_activity()
        entities = _make_entities_for(ocsf)
        writer.record(ocsf, entities, event_id=1)
        writer.stop()

        import sqlite3
        conn = sqlite3.connect(str(writer.db_path))
        row = conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()
        conn.close()
        assert row[0] == 1

    def test_ttl_pruning(self, tmp_path):
        """Records older than TTL are pruned."""
        writer = LedgerWriter(tmp_path, ttl_hours=1)
        try:
            ocsf = _make_process_activity()
            entities = _make_entities_for(ocsf)
            writer.record(ocsf, entities, event_id=1)
            time.sleep(1.5)

            # Insert a stale row directly
            import sqlite3
            conn = sqlite3.connect(str(writer.db_path))
            old_ts = time.time() - 7200  # 2 hours ago
            conn.execute(
                "INSERT INTO forensic_ledger (ts, event_type, ocsf_json) VALUES (?, 'old', '{}')",
                (old_ts,),
            )
            conn.commit()

            # Trigger prune
            writer._prune(conn)
            row = conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()
            conn.close()
            assert row[0] == 1  # Only the fresh row remains
        finally:
            writer.stop()

    def test_queue_full_does_not_crash(self, tmp_path):
        """When queue is full, record() logs a warning but does not crash."""
        writer = LedgerWriter(tmp_path, queue_size=10)
        try:
            ocsf = _make_process_activity()
            entities = _make_entities_for(ocsf)
            # Flood the queue (should not raise)
            for i in range(100):
                writer.record(ocsf, entities, event_id=i)
        finally:
            writer.stop()


# ── Reader Tests ──


class TestLedgerReader:
    def _write_and_flush(self, tmp_path, events):
        """Write events and wait for flush. Returns LedgerReader."""
        writer = LedgerWriter(tmp_path)
        for i, (ocsf, entities) in enumerate(events):
            writer.record(ocsf, entities, event_id=i)
        time.sleep(1.5)
        writer.stop()
        return LedgerReader(tmp_path)

    def test_query_time_range(self, tmp_path):
        """query_time_range returns events within the range."""
        ocsf = _make_process_activity()
        entities = _make_entities_for(ocsf)
        reader = self._write_and_flush(tmp_path, [(ocsf, entities)])

        now = time.time()
        rows = reader.query_time_range(now - 60, now + 60)
        assert len(rows) == 1
        assert rows[0].event_type == "ProcessActivity"
        assert rows[0].pid == 1234

    def test_query_time_range_with_event_type_filter(self, tmp_path):
        """query_time_range filters by event_types."""
        events = []
        for factory in [_make_process_activity, _make_network_activity]:
            ocsf = factory()
            events.append((ocsf, _make_entities_for(ocsf)))
        reader = self._write_and_flush(tmp_path, events)

        now = time.time()
        rows = reader.query_time_range(now - 60, now + 60, event_types=["NetworkActivity"])
        assert len(rows) == 1
        assert rows[0].event_type == "NetworkActivity"

    def test_query_by_pid(self, tmp_path):
        """query_by_pid returns events for a specific PID."""
        ocsf = _make_process_activity()
        entities = _make_entities_for(ocsf)
        reader = self._write_and_flush(tmp_path, [(ocsf, entities)])

        rows = reader.query_by_pid(1234)
        assert len(rows) == 1
        assert rows[0].process_name == "bash"

    def test_query_by_ip(self, tmp_path):
        """query_by_ip returns events with matching remote_ip."""
        ocsf = _make_network_activity()
        entities = _make_entities_for(ocsf)
        reader = self._write_and_flush(tmp_path, [(ocsf, entities)])

        rows = reader.query_by_ip("93.184.216.34")
        assert len(rows) == 1
        assert rows[0].remote_port == 443

    def test_get_stats(self, tmp_path):
        """get_stats returns correct counts."""
        ocsf = _make_process_activity()
        entities = _make_entities_for(ocsf)
        reader = self._write_and_flush(tmp_path, [(ocsf, entities)])

        stats = reader.get_stats()
        assert stats["row_count"] == 1
        assert stats["oldest_ts"] is not None
        assert stats["db_size_bytes"] > 0

    def test_deserialization_in_reader(self, tmp_path):
        """Reader deserializes ocsf and entities fields."""
        ocsf = _make_network_activity()
        entities = _make_entities_for(ocsf)
        reader = self._write_and_flush(tmp_path, [(ocsf, entities)])

        rows = reader.query_by_pid(5678)
        assert len(rows) == 1
        row = rows[0]
        # Deserialized OCSF
        assert row.ocsf is not None
        assert row.ocsf.class_uid == 4001
        assert row.ocsf.process.name == "curl"
        # Deserialized entities
        assert row.entities is not None
        assert len(row.entities.ips) == 1
        assert row.entities.ips[0].address == "93.184.216.34"

    def test_iter_entities(self, tmp_path):
        """iter_entities yields ExtractedEntities for time range."""
        events = []
        for factory in [_make_process_activity, _make_network_activity, _make_dns_activity]:
            ocsf = factory()
            events.append((ocsf, _make_entities_for(ocsf)))
        reader = self._write_and_flush(tmp_path, events)

        now = time.time()
        results = list(reader.iter_entities(now - 60, now + 60))
        assert len(results) == 3
        # Each should be an ExtractedEntities
        for ent in results:
            assert isinstance(ent, ExtractedEntities)

    def test_empty_ledger(self, tmp_path):
        """Reader handles empty ledger gracefully."""
        # Create DB via writer, then read empty
        writer = LedgerWriter(tmp_path)
        writer.stop()
        reader = LedgerReader(tmp_path)

        rows = reader.query_by_pid(9999)
        assert rows == []

        stats = reader.get_stats()
        assert stats["row_count"] == 0


# ── Full Round-Trip Tests ──


class TestFullRoundTrip:
    """Write to ledger via writer, read back via reader, verify fidelity."""

    @pytest.mark.parametrize("factory", [
        _make_process_activity,
        _make_network_activity,
        _make_authentication,
        _make_dns_activity,
        _make_file_activity,
        _make_registry_activity,
    ])
    def test_full_roundtrip_all_types(self, tmp_path, factory):
        """Full write->read->deserialize round-trip for each OCSF type."""
        ocsf = factory()
        entities = _make_entities_for(ocsf)

        writer = LedgerWriter(tmp_path)
        writer.record(ocsf, entities, event_id=42)
        time.sleep(1.5)
        writer.stop()

        reader = LedgerReader(tmp_path)
        now = time.time()
        rows = reader.query_time_range(now - 60, now + 60)
        assert len(rows) == 1

        row = rows[0]
        assert row.event_type == type(ocsf).__name__
        # Deserialized OCSF should match original type
        assert row.ocsf is not None
        assert type(row.ocsf) is type(ocsf)
        assert row.ocsf.class_uid == ocsf.class_uid
