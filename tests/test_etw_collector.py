"""Tests for the Windows ETW collector."""

import sys
from datetime import datetime
from unittest.mock import patch, MagicMock

from agent.collectors.etw_collector import (
    EtwCollector,
    _classify_event,
    _extract_fields,
)
from agent.collectors.base import RawEvent


class TestEtwCollector:
    def test_buffer_drain(self):
        """collect() drains the internal buffer."""
        collector = EtwCollector()
        # Manually insert events into the buffer
        ev = RawEvent(
            timestamp=datetime.now(),
            source="etw_process",
            message="test",
            fields={"pid": "1234"},
            hostname="testhost",
        )
        collector._buffer.append(ev)
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 2
        # Buffer should be empty after drain
        assert len(collector._buffer) == 0
        assert collector.collect() == []

    def test_event_classification(self):
        """_classify_event maps provider names to source taxonomy."""
        assert _classify_event({"ProviderName": "Microsoft-Windows-Kernel-Process"}) == "etw_process"
        assert _classify_event({"ProviderName": "Microsoft-Windows-Kernel-Network"}) == "etw_network"
        assert _classify_event({"ProviderName": "Microsoft-Windows-DNS-Client"}) == "etw_dns"
        assert _classify_event({"ProviderName": "Microsoft-Windows-Kernel-File"}) == "etw_file"
        assert _classify_event({"ProviderName": "Microsoft-Windows-Kernel-Registry"}) == "etw_registry"
        # Unknown provider falls back to etw_process
        assert _classify_event({"ProviderName": "SomeUnknown"}) == "etw_process"

    def test_field_extraction(self):
        """_extract_fields maps ETW fields to common field names."""
        event_data = {
            "ProcessId": 5678,
            "ImageFileName": "cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "DestAddress": "10.0.0.1",
            "DestPort": 443,
        }
        fields = _extract_fields(event_data)
        assert fields["pid"] == "5678"
        assert fields["name"] == "cmd.exe"
        assert fields["cmdline"] == "cmd.exe /c whoami"
        assert fields["dst_ip"] == "10.0.0.1"
        assert fields["dst_port"] == "443"

    def test_import_guard_non_windows(self):
        """EtwCollector can be imported on any platform (pywintrace is lazy)."""
        collector = EtwCollector()
        assert collector.name() == "etw"
        # start() should handle missing pywintrace gracefully
        collector.start()
        # Give the thread a moment, then stop
        import time
        time.sleep(0.05)
        collector.stop()
