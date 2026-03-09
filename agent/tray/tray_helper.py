#!/usr/bin/env python3
"""Standalone macOS menu bar tray helper for EDR Graph Agent.

Fully self-contained — no imports from the agent package. Only requires
``rumps`` (pip install rumps). Runs as a user-level LaunchAgent and talks
to the root daemon via localhost HTTP endpoints.

Usage:
    python3 tray_helper.py [--health-port 9100] [--dashboard-port 9200]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import struct
import sys
import tempfile
import time
import urllib.request
import zlib
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("edr-tray")

try:
    import rumps
except ImportError:
    print("Error: rumps is required. Install with: pip3 install rumps", file=sys.stderr)
    sys.exit(1)


# ── Embedded icons (12x12 PNG circles) ──────────────────────────────────


def _make_circle_png(r: int, g: int, b: int) -> bytes:
    """Generate a tiny 12x12 PNG with a filled circle of the given colour."""
    size = 12
    rows = bytearray()
    cx, cy = size / 2 - 0.5, size / 2 - 0.5
    radius = size / 2 - 1
    for y in range(size):
        rows.append(0)
        for x in range(size):
            dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if dist <= radius:
                rows.extend([r, g, b, 255])
            elif dist <= radius + 1:
                alpha = max(0, min(255, int(255 * (radius + 1 - dist))))
                rows.extend([r, g, b, alpha])
            else:
                rows.extend([0, 0, 0, 0])

    def _chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(rows))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _icon_path(data: bytes, name: str) -> str:
    fd, path = tempfile.mkstemp(prefix=f"edr_icon_{name}_", suffix=".png")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


_ICON_GREEN = _make_circle_png(34, 197, 94)
_ICON_ORANGE = _make_circle_png(249, 115, 22)
_ICON_RED = _make_circle_png(239, 68, 68)
_ICON_GRAY = _make_circle_png(156, 163, 175)


def _format_uptime(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    remaining_min = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_min}m"
    days = hours // 24
    remaining_hours = hours % 24
    return f"{days}d {remaining_hours}h"


# ── HTTP helper ──────────────────────────────────────────────────────────


def _fetch_json(url: str, timeout: float = 3) -> dict | list | None:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


# ── Tray app ─────────────────────────────────────────────────────────────


class EDRTrayHelper(rumps.App):
    """Standalone tray icon that polls the agent daemon's HTTP API."""

    def __init__(self, health_port: int = 9100, dashboard_port: int = 9200):
        self._health_url = f"http://127.0.0.1:{health_port}/health"
        self._status_url = f"http://127.0.0.1:{dashboard_port}/api/status"
        self._findings_url = f"http://127.0.0.1:{dashboard_port}/api/findings?limit=200"
        self._dashboard_url = f"http://127.0.0.1:{dashboard_port}/"

        self._icon_paths = {
            "green": _icon_path(_ICON_GREEN, "green"),
            "orange": _icon_path(_ICON_ORANGE, "orange"),
            "red": _icon_path(_ICON_RED, "red"),
            "gray": _icon_path(_ICON_GRAY, "gray"),
        }
        self._current_icon = "gray"

        super().__init__(
            "EDR Graph Agent",
            icon=self._icon_paths["gray"],
            quit_button=None,
        )

        self._status_item = rumps.MenuItem("Agent: Connecting...")
        self._events_item = rumps.MenuItem("Events: —")
        self._findings_item = rumps.MenuItem("Findings: —")
        self._last_alert_item = rumps.MenuItem("Last Alert: None")
        self._open_dashboard = rumps.MenuItem(
            "Open Dashboard", callback=self._on_open_dashboard, key="d"
        )
        self._quit_item = rumps.MenuItem("Quit Tray", callback=self._on_quit)

        self.menu = [
            self._status_item,
            self._events_item,
            None,
            self._findings_item,
            self._last_alert_item,
            None,
            self._open_dashboard,
            None,
            self._quit_item,
        ]

        self._last_notification: dict[str, float] = {}
        self._notification_cooldown = 60
        self._seen_finding_ids: set[str] = set()

    def _on_open_dashboard(self, _sender: Any) -> None:
        import webbrowser
        webbrowser.open(self._dashboard_url)

    def _on_quit(self, _sender: Any) -> None:
        rumps.quit_application()

    @rumps.timer(3)
    def _poll(self, _timer: Any) -> None:
        """Poll agent endpoints every 3 seconds."""
        health = _fetch_json(self._health_url)
        if not health:
            self._status_item.title = "Agent: Not Running"
            self._events_item.title = "Events: —"
            self._set_icon("gray")
            return

        status = _fetch_json(self._status_url)
        if status:
            uptime = status.get("uptime_seconds", health.get("uptime_seconds", 0))
            uptime_str = _format_uptime(uptime)
            agent_status = status.get("status", "running")
            self._status_item.title = f"Agent: {agent_status.title()} ({uptime_str})"

            events = status.get("events_processed", 0)
            eps = status.get("events_per_second", 0)
            self._events_item.title = f"Events: {events:,} ({eps}/sec)"
        else:
            uptime_str = _format_uptime(health.get("uptime_seconds", 0))
            self._status_item.title = f"Agent: Running ({uptime_str})"

        findings_data = _fetch_json(self._findings_url)
        if findings_data and isinstance(findings_data, list):
            total = len(findings_data)
            high = sum(1 for f in findings_data if (f.get("severity") or "").lower() == "high")
            critical = sum(1 for f in findings_data if (f.get("severity") or "").lower() == "critical")

            parts = [f"{total} total"]
            if high:
                parts.append(f"{high} HIGH")
            if critical:
                parts.append(f"{critical} CRITICAL")
            self._findings_item.title = f"Findings: {', '.join(parts)}"

            if findings_data:
                self._last_alert_item.title = f"Last Alert: {findings_data[0].get('title', '—')}"

            now = time.time()
            for f in findings_data:
                fid = f.get("id", "")
                sev = (f.get("severity") or "").upper()
                if fid in self._seen_finding_ids:
                    continue
                self._seen_finding_ids.add(fid)
                if sev not in ("CRITICAL", "HIGH"):
                    continue
                last = self._last_notification.get(sev, 0)
                if now - last < self._notification_cooldown:
                    continue
                self._last_notification[sev] = now
                rumps.notification(
                    title=f"EDR {sev} Alert",
                    subtitle="",
                    message=f.get("title", "Detection"),
                    sound=sev == "CRITICAL",
                )

            one_hour_ago = time.time() - 3600
            if self._last_notification.get("CRITICAL", 0) > one_hour_ago:
                self._set_icon("red")
            elif self._last_notification.get("HIGH", 0) > one_hour_ago:
                self._set_icon("orange")
            else:
                self._set_icon("green")
        else:
            self._findings_item.title = "Findings: —"
            if health:
                self._set_icon("green")

    def _set_icon(self, color: str) -> None:
        if color != self._current_icon:
            self._current_icon = color
            self.icon = self._icon_paths.get(color, self._icon_paths["green"])


def main() -> None:
    parser = argparse.ArgumentParser(description="EDR Graph Agent tray icon")
    parser.add_argument("--health-port", type=int, default=9100)
    parser.add_argument("--dashboard-port", type=int, default=9200)
    args = parser.parse_args()

    app = EDRTrayHelper(health_port=args.health_port, dashboard_port=args.dashboard_port)
    app.run()


if __name__ == "__main__":
    main()
