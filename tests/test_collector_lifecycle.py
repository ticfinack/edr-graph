"""Tests for collector lifecycle (start/stop) methods."""

from unittest.mock import patch, MagicMock

from agent.collectors.base import Collector, RawEvent
from agent.collectors.psutil_collector import PsutilCollector


class TestDefaultLifecycle:
    """Default start()/stop() are no-ops and don't raise."""

    def test_default_start_is_noop(self):
        collector = PsutilCollector()
        collector.start()  # should not raise

    def test_default_stop_is_noop(self):
        collector = PsutilCollector()
        collector.stop()  # should not raise

    def test_psutil_lifecycle_roundtrip(self):
        collector = PsutilCollector()
        collector.start()
        events = collector.collect()
        assert isinstance(events, list)
        collector.stop()


class TestMacOSLifecycle:
    @patch("agent.collectors.macos.subprocess.Popen")
    def test_start_creates_stream_thread(self, mock_popen):
        from agent.collectors.macos import MacOSCollector

        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_popen.return_value = mock_proc

        collector = MacOSCollector()
        assert collector._stream_thread is None
        collector.start()
        assert collector._stream_thread is not None
        collector.stop()
