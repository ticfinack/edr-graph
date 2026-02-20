"""Tests for Phase 8: Dashboard backend, frontend, tray icon, and integration."""

from __future__ import annotations

import collections
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Dashboard backend tests ──────────────────────────────────────────────


class TestDashboardServer:
    """Test FastAPI dashboard server endpoints."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        """Set up a test queue and dashboard state."""
        from agent.dashboard import server

        # Create a mock queue
        self.mock_queue = MagicMock()
        self.mock_queue.count_unprocessed.return_value = 10
        self.mock_queue.get_findings.return_value = []

        # Store original state
        self._orig_state = dict(server._state)
        self._orig_events = list(server.recent_events)

        # Initialize dashboard state
        server._state["queue"] = self.mock_queue
        server._state["kuzu_db"] = None  # Graph endpoints will fail gracefully
        server._state["settings"] = None
        server._state["start_time"] = time.time()
        server._state["paused"] = False
        server._state["collector_names"] = ["PsutilCollector", "MacOSCollector"]

        server.recent_events.clear()

        yield

        # Restore state
        server._state.update(self._orig_state)
        server.recent_events.clear()
        server.recent_events.extend(self._orig_events)

    def test_index_serves_html(self):
        """GET / should serve the index.html file."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_index_html_contains_tabs(self):
        """The index.html should contain all 6 tab sections."""
        index_path = Path(__file__).parent.parent / "agent" / "dashboard" / "static" / "index.html"
        if not index_path.exists():
            pytest.skip("index.html not found")

        html = index_path.read_text()
        for tab in ["overview", "findings", "graph", "events", "audit", "settings"]:
            assert tab in html.lower(), f"Tab '{tab}' not found in index.html"

    def test_index_no_external_requests(self):
        """The index.html should have no external CDN dependencies."""
        index_path = Path(__file__).parent.parent / "agent" / "dashboard" / "static" / "index.html"
        if not index_path.exists():
            pytest.skip("index.html not found")

        html = index_path.read_text()
        # Should not reference external CDNs
        assert "cdn." not in html.lower()
        assert "unpkg.com" not in html.lower()
        assert "jsdelivr" not in html.lower()

    def test_api_status(self):
        """GET /api/status should return agent status."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "agent_status" in data
        assert "uptime_seconds" in data
        assert "events_processed" in data
        assert "queue_depth" in data
        assert data["agent_status"] == "running"

    def test_api_status_paused(self):
        """GET /api/status should reflect paused state."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import _state, app

        _state["paused"] = True
        client = TestClient(app)
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.json()["agent_status"] == "paused"

    def test_api_findings_empty(self):
        """GET /api/findings should return empty list when no findings."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/api/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings"] == []
        assert "total" in data

    def test_api_events_recent(self):
        """GET /api/events/recent should return recent events."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app, append_recent_event

        # Add some test events
        append_recent_event({"source": "test", "event_type": "test_event", "timestamp": "2024-01-01"})
        append_recent_event({"source": "test2", "event_type": "other", "timestamp": "2024-01-02"})

        client = TestClient(app)
        resp = client.get("/api/events/recent")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) == 2

    def test_api_events_filter_by_source(self):
        """GET /api/events/recent should filter by source."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app, append_recent_event

        append_recent_event({"source": "dns", "event_type": "dns_resolve"})
        append_recent_event({"source": "psutil", "event_type": "process_start"})

        client = TestClient(app)
        resp = client.get("/api/events/recent?source=dns")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) == 1
        assert data["events"][0]["source"] == "dns"

    def test_api_pause_resume(self):
        """POST /api/pause and /api/resume should toggle pause state."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import _state, app

        client = TestClient(app)

        # Pause
        resp = client.post("/api/pause")
        assert resp.status_code == 200
        assert resp.json()["paused"] is True
        assert _state["paused"] is True

        # Resume
        resp = client.post("/api/resume")
        assert resp.status_code == 200
        assert resp.json()["paused"] is False
        assert _state["paused"] is False

    def test_api_metrics(self):
        """GET /api/metrics should return Prometheus metrics as JSON."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_api_graph_stats_no_db(self):
        """GET /api/graph/stats should return 503 when no graph DB."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/api/graph/stats")
        assert resp.status_code == 503

    def test_api_settings_no_settings(self):
        """GET /api/settings should return empty dict when no settings."""
        from fastapi.testclient import TestClient

        from agent.dashboard.server import app

        client = TestClient(app)
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_notification_queue(self):
        """Notification queue should accept findings."""
        from agent.dashboard.server import notification_queue

        notification_queue.appendleft({
            "severity": "CRITICAL",
            "title": "Test finding",
            "id": "test-1",
            "timestamp": time.time(),
        })
        assert len(notification_queue) == 1
        item = notification_queue.pop()
        assert item["severity"] == "CRITICAL"

    def test_append_recent_event_thread_safe(self):
        """append_recent_event should be thread-safe."""
        import threading

        from agent.dashboard.server import append_recent_event, recent_events

        errors = []

        def _append(n):
            try:
                for i in range(100):
                    append_recent_event({"source": f"thread-{n}", "i": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_append, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Should have at most maxlen events
        assert len(recent_events) <= 1000

    def test_init_dashboard(self):
        """init_dashboard should set shared state."""
        from agent.dashboard.server import _state, init_dashboard

        mock_queue = MagicMock()
        mock_db = MagicMock()
        mock_settings = MagicMock()

        init_dashboard(mock_queue, mock_db, mock_settings, ["Collector1"])

        assert _state["queue"] is mock_queue
        assert _state["kuzu_db"] is mock_db
        assert _state["settings"] is mock_settings
        assert _state["collector_names"] == ["Collector1"]


# ── Tray icon tests ─────────────────────────────────────────────────────


class TestTrayIcon:
    """Test macOS tray icon module."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_tray_module_imports(self):
        """The tray module should import correctly on macOS."""
        from agent.tray import macos_tray
        assert hasattr(macos_tray, "EDRTrayApp")

    def test_tray_skips_non_macos(self):
        """Tray initialization should work gracefully without rumps."""
        from agent.tray.macos_tray import EDRTrayApp

        if sys.platform != "darwin":
            with pytest.raises(ImportError, match="rumps"):
                EDRTrayApp()

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_notification_rate_limiting(self):
        """Two CRITICAL findings within 60s should only produce 1 notification."""
        from agent.tray.macos_tray import EDRTrayApp

        with patch("agent.tray.macos_tray.rumps") as mock_rumps:
            mock_rumps.App = MagicMock()
            mock_rumps.MenuItem = MagicMock()
            mock_rumps.Timer = MagicMock()

            app = EDRTrayApp(notification_cooldown=60)

            # Simulate two findings in rapid succession
            app.notification_queue.appendleft({
                "severity": "CRITICAL",
                "title": "Finding 1",
                "timestamp": time.time(),
            })
            app.notification_queue.appendleft({
                "severity": "CRITICAL",
                "title": "Finding 2",
                "timestamp": time.time(),
            })

            app._dispatch_notifications()

            # Should only have sent 1 notification
            assert mock_rumps.notification.call_count == 1
            call_args = mock_rumps.notification.call_args
            assert "CRITICAL" in call_args.kwargs.get("title", call_args[1].get("title", ""))

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_notification_different_severities(self):
        """CRITICAL and HIGH findings should each produce a notification."""
        from agent.tray.macos_tray import EDRTrayApp

        with patch("agent.tray.macos_tray.rumps") as mock_rumps:
            mock_rumps.App = MagicMock()
            mock_rumps.MenuItem = MagicMock()
            mock_rumps.Timer = MagicMock()

            app = EDRTrayApp(notification_cooldown=60)

            app.notification_queue.appendleft({
                "severity": "CRITICAL",
                "title": "Critical Finding",
                "timestamp": time.time(),
            })
            app.notification_queue.appendleft({
                "severity": "HIGH",
                "title": "High Finding",
                "timestamp": time.time(),
            })

            app._dispatch_notifications()

            # Should have sent 2 notifications (different severities)
            assert mock_rumps.notification.call_count == 2

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_medium_findings_not_notified(self):
        """MEDIUM findings should not trigger macOS notifications."""
        from agent.tray.macos_tray import EDRTrayApp

        with patch("agent.tray.macos_tray.rumps") as mock_rumps:
            mock_rumps.App = MagicMock()
            mock_rumps.MenuItem = MagicMock()
            mock_rumps.Timer = MagicMock()

            app = EDRTrayApp(notification_cooldown=60)

            app.notification_queue.appendleft({
                "severity": "MEDIUM",
                "title": "Medium Finding",
                "timestamp": time.time(),
            })

            app._dispatch_notifications()

            assert mock_rumps.notification.call_count == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_push_finding(self):
        """push_finding should add to the notification queue."""
        from agent.tray.macos_tray import EDRTrayApp

        with patch("agent.tray.macos_tray.rumps") as mock_rumps:
            mock_rumps.App = MagicMock()
            mock_rumps.MenuItem = MagicMock()
            mock_rumps.Timer = MagicMock()

            app = EDRTrayApp()

            finding = MagicMock()
            finding.severity = "HIGH"
            finding.title = "Test Finding"
            finding.id = "test-123"

            app.push_finding(finding)

            assert len(app.notification_queue) == 1
            item = app.notification_queue.pop()
            assert item["severity"] == "HIGH"
            assert item["title"] == "Test Finding"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_icon_state_changes(self):
        """Tray icon should change color based on findings."""
        from agent.tray.macos_tray import EDRTrayApp

        with patch("agent.tray.macos_tray.rumps") as mock_rumps:
            mock_rumps.App = MagicMock()
            mock_rumps.MenuItem = MagicMock()
            mock_rumps.Timer = MagicMock()

            # Provide a status_callback so _update_icon_from_findings doesn't return early
            app = EDRTrayApp(status_callback=lambda: {"agent_status": "running"})
            assert app._current_icon == "green"

            # Simulate a CRITICAL notification
            app._last_notification["CRITICAL"] = time.time()
            app._update_icon_from_findings()
            assert app._current_icon == "red"

            # Simulate only HIGH (no recent CRITICAL)
            app._last_notification["CRITICAL"] = 0
            app._last_notification["HIGH"] = time.time()
            app._update_icon_from_findings()
            assert app._current_icon == "orange"


# ── Icon generation tests ────────────────────────────────────────────────


class TestIconGeneration:
    """Test programmatic PNG icon generation."""

    def test_circle_png_valid(self):
        """Generated PNGs should be valid PNG files."""
        from agent.tray.macos_tray import _make_circle_png

        png = _make_circle_png(255, 0, 0)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic bytes
        assert len(png) > 50  # Sanity check for minimum size

    def test_all_icon_colors(self):
        """All four icon colors should produce valid PNGs."""
        from agent.tray.macos_tray import _ICON_GRAY, _ICON_GREEN, _ICON_ORANGE, _ICON_RED

        for icon in [_ICON_GREEN, _ICON_ORANGE, _ICON_RED, _ICON_GRAY]:
            assert icon[:8] == b"\x89PNG\r\n\x1a\n"


# ── Uptime formatter tests ──────────────────────────────────────────────


class TestUptimeFormatter:
    """Test the _format_uptime helper."""

    def test_seconds(self):
        from agent.tray.macos_tray import _format_uptime
        assert _format_uptime(30) == "30s"

    def test_minutes(self):
        from agent.tray.macos_tray import _format_uptime
        assert _format_uptime(150) == "2m"

    def test_hours(self):
        from agent.tray.macos_tray import _format_uptime
        assert _format_uptime(7500) == "2h 5m"

    def test_days(self):
        from agent.tray.macos_tray import _format_uptime
        assert _format_uptime(90000) == "1d 1h"


# ── Config tests ─────────────────────────────────────────────────────────


class TestPhase8Config:
    """Test new Phase 8 config settings."""

    def test_default_dashboard_port(self):
        """Default dashboard port should be 9200."""
        from agent.config import Settings
        s = Settings()
        assert s.dashboard_port == 9200

    def test_tray_settings_defaults(self):
        """Tray settings should have sensible defaults."""
        from agent.config import Settings
        s = Settings()
        assert s.tray_enabled is True
        assert s.tray_notification_cooldown == 60
        assert s.tray_notify_on_high is True
        assert s.tray_notify_on_critical is True

    def test_dashboard_auto_open_default(self):
        """Dashboard auto-open should default to True."""
        from agent.config import Settings
        s = Settings()
        assert s.dashboard_auto_open is True

    def test_yaml_key_map_has_tray_keys(self):
        """YAML key map should include tray settings."""
        from agent.config import _YAML_KEY_MAP
        tray_keys = [k for k in _YAML_KEY_MAP if k[0] == "tray"]
        assert len(tray_keys) >= 3  # enabled, cooldown, notify_on_high, notify_on_critical

    def test_generate_config_includes_tray(self):
        """Generated config should include tray section."""
        from agent.config import generate_default_config
        config = generate_default_config()
        assert "tray:" in config
        assert "notification_cooldown_seconds" in config


# ── Integration tests ────────────────────────────────────────────────────


class TestPhase8Integration:
    """Test integration between components."""

    def test_main_module_has_no_nicegui_import(self):
        """main.py should not import NiceGUI anymore."""
        main_path = Path(__file__).parent.parent / "agent" / "main.py"
        content = main_path.read_text()
        assert "nicegui" not in content.lower()

    def test_pyproject_has_fastapi(self):
        """pyproject.toml should list fastapi as a dependency."""
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject_path.read_text()
        assert "fastapi" in content
        assert "uvicorn" in content

    def test_pyproject_has_rumps(self):
        """pyproject.toml should list rumps as a macOS dependency."""
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject_path.read_text()
        assert "rumps" in content

    def test_pyproject_no_nicegui(self):
        """pyproject.toml should not have NiceGUI dependency."""
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject_path.read_text()
        assert "nicegui" not in content.lower()

    def test_dashboard_server_imports(self):
        """Dashboard server module should import cleanly."""
        from agent.dashboard.server import app, init_dashboard, start_dashboard_server
        assert app is not None
        assert callable(init_dashboard)
        assert callable(start_dashboard_server)

    def test_is_paused_default_false(self):
        """_is_paused should default to False."""
        from agent.main import _is_paused
        assert _is_paused() is False

    def test_push_recent_event(self):
        """_push_recent_event should add to dashboard buffer."""
        from agent.dashboard.server import recent_events
        from agent.main import _push_recent_event

        initial_len = len(recent_events)
        _push_recent_event(
            {"source": "test", "event_type": "test", "timestamp": "now", "name": "test"},
            "test",
        )
        assert len(recent_events) == initial_len + 1
