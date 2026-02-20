"""Tests for process node deduplication in entity extraction.

Verifies that the _resolve_start_time cache prevents duplicate Process
nodes when multiple event types reference the same running process.
"""

from __future__ import annotations

import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Mock kuzu and psutil before importing agent.processor (which imports graph_builder -> kuzu)
# These may or may not be installed in the test environment.
_mock_psutil_mod = MagicMock()
_original_psutil = sys.modules.get("psutil")
_original_kuzu = sys.modules.get("kuzu")

if "kuzu" not in sys.modules:
    sys.modules["kuzu"] = MagicMock()
# Always install our mock psutil so we control Process() behavior
sys.modules["psutil"] = _mock_psutil_mod

from agent.schema.ocsf_types import (  # noqa: E402
    DeviceInfo,
    DnsActivity,
    FileActivity,
    NetworkActivity,
    NetworkEndpoint,
    OcsfMetadata,
    ProcessActivity,
    ProcessInfo,
)


def _setup_psutil_mock(create_time=1700000000.0, ppid=1, raise_error=False):
    """Configure the global psutil mock's Process class."""
    if raise_error:
        _mock_psutil_mod.Process.side_effect = Exception("NoSuchProcess")
        return

    mock_proc = MagicMock()
    mock_proc.create_time.return_value = create_time
    mock_proc.ppid.return_value = ppid
    mock_proc.cmdline.return_value = ["/usr/bin/curl"]
    mock_proc.exe.return_value = "/usr/bin/curl"
    mock_proc.name.return_value = "curl"
    _mock_psutil_mod.Process.side_effect = None
    _mock_psutil_mod.Process.return_value = mock_proc
    _mock_psutil_mod.AccessDenied = type("AccessDenied", (Exception,), {})
    _mock_psutil_mod.ZombieProcess = type("ZombieProcess", (Exception,), {})
    _mock_psutil_mod.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
    return mock_proc


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear entity_extractor caches before each test."""
    from agent.processor import entity_extractor

    entity_extractor._ppid_cache.clear()
    entity_extractor._create_time_cache.clear()
    # Reset the psutil mock
    _mock_psutil_mod.reset_mock()
    _mock_psutil_mod.Process.side_effect = None
    yield
    entity_extractor._ppid_cache.clear()
    entity_extractor._create_time_cache.clear()


class TestResolveStartTime:
    def test_returns_psutil_create_time(self):
        from agent.processor.entity_extractor import _resolve_start_time

        _setup_psutil_mock(create_time=1700000000.0)
        result = _resolve_start_time(42, datetime(2025, 1, 1))
        assert result == datetime.fromtimestamp(1700000000.0)

    def test_caches_create_time(self):
        from agent.processor.entity_extractor import _resolve_start_time, _create_time_cache

        _setup_psutil_mock(create_time=1700000000.0)
        _resolve_start_time(42, datetime(2025, 1, 1))
        assert 42 in _create_time_cache
        assert _create_time_cache[42] == 1700000000.0

    def test_uses_cache_for_dead_process(self):
        from agent.processor.entity_extractor import _resolve_start_time, _create_time_cache

        # First call succeeds — caches the value
        _setup_psutil_mock(create_time=1700000000.0)
        _resolve_start_time(42, datetime(2025, 1, 1))

        # Second call: process is dead (psutil raises)
        _setup_psutil_mock(raise_error=True)
        result = _resolve_start_time(42, datetime(2025, 6, 1))

        # Should use cached value, not the fallback
        assert result == datetime.fromtimestamp(1700000000.0)

    def test_fallback_for_unknown_dead_process(self):
        from agent.processor.entity_extractor import _resolve_start_time

        fallback = datetime(2025, 1, 1)
        _setup_psutil_mock(raise_error=True)
        result = _resolve_start_time(999, fallback)
        assert result == fallback

    def test_marks_dead_process_as_unresolvable(self):
        from agent.processor.entity_extractor import _resolve_start_time, _create_time_cache

        _setup_psutil_mock(raise_error=True)
        _resolve_start_time(999, datetime(2025, 1, 1))
        assert _create_time_cache[999] == 0

    def test_handles_pid_reuse(self):
        from agent.processor.entity_extractor import _resolve_start_time, _create_time_cache

        # First process with PID 42 created at epoch 1700000000
        _setup_psutil_mock(create_time=1700000000.0)
        result1 = _resolve_start_time(42, datetime(2025, 1, 1))
        assert result1 == datetime.fromtimestamp(1700000000.0)

        # PID 42 gets reused — new process created at epoch 1700099999
        _setup_psutil_mock(create_time=1700099999.0)
        result2 = _resolve_start_time(42, datetime(2025, 1, 1))

        # Should return the NEW create time, not the old cached one
        assert result2 == datetime.fromtimestamp(1700099999.0)
        assert _create_time_cache[42] == 1700099999.0

    def test_returns_fallback_for_pid_zero(self):
        from agent.processor.entity_extractor import _resolve_start_time

        fallback = datetime(2025, 1, 1)
        result = _resolve_start_time(0, fallback)
        assert result == fallback

    def test_returns_fallback_for_negative_pid(self):
        from agent.processor.entity_extractor import _resolve_start_time

        fallback = datetime(2025, 1, 1)
        result = _resolve_start_time(-1, fallback)
        assert result == fallback


class TestProcessNodeDedup:
    """Integration test: multiple event types for the same PID produce the same Process ID."""

    def _make_process_event(self, pid=42, name="curl", hostname="test-host"):
        return ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0, 0),
            process=ProcessInfo(pid=pid, name=name, created_time=None),
            device=DeviceInfo(hostname=hostname),
            metadata=OcsfMetadata(original_time=datetime(2025, 1, 15, 10, 0, 0)),
        )

    def _make_network_event(self, pid=42, name="curl", hostname="test-host"):
        return NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 5, 0),
            process=ProcessInfo(pid=pid, name=name, created_time=None),
            dst_endpoint=NetworkEndpoint(ip="10.0.0.1", port=443),
            device=DeviceInfo(hostname=hostname),
            metadata=OcsfMetadata(original_time=datetime(2025, 1, 15, 10, 5, 0)),
        )

    def _make_dns_event(self, pid=42, name="curl", hostname="test-host"):
        return DnsActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 3, 0),
            process=ProcessInfo(pid=pid, name=name, created_time=None),
            query_domain="example.com",
            resolved_ips=[],
            device=DeviceInfo(hostname=hostname),
            metadata=OcsfMetadata(original_time=datetime(2025, 1, 15, 10, 3, 0)),
        )

    def _make_file_event(self, pid=42, name="curl", hostname="test-host"):
        return FileActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 7, 0),
            process=ProcessInfo(pid=pid, name=name, created_time=None),
            file_path="/tmp/output.txt",
            device=DeviceInfo(hostname=hostname),
            metadata=OcsfMetadata(original_time=datetime(2025, 1, 15, 10, 7, 0)),
        )

    def test_all_event_types_produce_same_process_id(self):
        """All event types for PID 42 should produce the same Process node ID."""
        from agent.processor.entity_extractor import extract_entities

        _setup_psutil_mock(create_time=1700000000.0)

        proc_event = self._make_process_event()
        net_event = self._make_network_event()
        dns_event = self._make_dns_event()
        file_event = self._make_file_event()

        proc_entities = extract_entities(proc_event, event_id=1)
        net_entities = extract_entities(net_event, event_id=2)
        dns_entities = extract_entities(dns_event, event_id=3)
        file_entities = extract_entities(file_event, event_id=4)

        # All should have produced exactly 1 process
        assert len(proc_entities.processes) == 1
        assert len(net_entities.processes) == 1
        assert len(dns_entities.processes) == 1
        assert len(file_entities.processes) == 1

        # All process IDs should be identical
        proc_ids = {
            proc_entities.processes[0].id,
            net_entities.processes[0].id,
            dns_entities.processes[0].id,
            file_entities.processes[0].id,
        }
        assert len(proc_ids) == 1, f"Expected 1 unique process ID, got {proc_ids}"

        # Verify the ID format uses the psutil create_time
        expected_id = f"test-host:42:{int(1700000000.0)}"
        assert proc_ids.pop() == expected_id

    def test_different_pids_produce_different_ids(self):
        """Different PIDs should get different Process node IDs."""
        from agent.processor.entity_extractor import extract_entities

        call_count = [0]
        def mock_process_factory(pid):
            call_count[0] += 1
            proc = MagicMock()
            proc.create_time.return_value = 1700000000.0 + pid
            proc.ppid.return_value = 1
            proc.cmdline.return_value = []
            proc.exe.return_value = ""
            proc.name.return_value = "test"
            return proc

        _mock_psutil_mod.Process.side_effect = mock_process_factory
        _mock_psutil_mod.AccessDenied = type("AccessDenied", (Exception,), {})
        _mock_psutil_mod.ZombieProcess = type("ZombieProcess", (Exception,), {})

        event1 = self._make_network_event(pid=42, name="curl")
        event2 = self._make_network_event(pid=43, name="wget")

        entities1 = extract_entities(event1, event_id=1)
        entities2 = extract_entities(event2, event_id=2)

        assert entities1.processes[0].id != entities2.processes[0].id

    def test_event_with_created_time_uses_it(self):
        """When an event already has created_time, use it instead of psutil lookup."""
        from agent.processor.entity_extractor import extract_entities

        known_time = datetime(2025, 1, 1, 0, 0, 0)
        event = ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0, 0),
            process=ProcessInfo(
                pid=42, name="curl", created_time=known_time,
            ),
            device=DeviceInfo(hostname="test-host"),
            metadata=OcsfMetadata(original_time=datetime(2025, 1, 15, 10, 0, 0)),
        )

        # Set up psutil mock (it may still be called by _enrich_process_node)
        _setup_psutil_mock(create_time=9999999999.0)
        entities = extract_entities(event, event_id=1)

        # The process ID should use the event's created_time, NOT psutil's
        expected_id = f"test-host:42:{int(known_time.timestamp())}"
        assert entities.processes[0].id == expected_id

    def test_dead_process_events_use_consistent_fallback(self):
        """Multiple events for a dead process (no psutil) should still share an ID."""
        from agent.processor.entity_extractor import extract_entities, _create_time_cache

        # Simulate: PID 42 was once alive, we cached its create_time, now it's dead
        _create_time_cache[42] = 1700000000.0

        _setup_psutil_mock(raise_error=True)

        event1 = self._make_network_event(pid=42)
        event2 = self._make_dns_event(pid=42)

        entities1 = extract_entities(event1, event_id=1)
        entities2 = extract_entities(event2, event_id=2)

        assert entities1.processes[0].id == entities2.processes[0].id
        expected_id = f"test-host:42:{int(1700000000.0)}"
        assert entities1.processes[0].id == expected_id


def teardown_module():
    """Restore original sys.modules entries after all tests in this module."""
    if _original_psutil is not None:
        sys.modules["psutil"] = _original_psutil
    else:
        sys.modules.pop("psutil", None)
    if _original_kuzu is not None:
        sys.modules["kuzu"] = _original_kuzu
    else:
        sys.modules.pop("kuzu", None)
