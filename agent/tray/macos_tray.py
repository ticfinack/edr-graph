"""macOS menu bar tray icon for EDR Graph Agent.

Uses ``rumps`` for a native macOS menu bar app.  The tray icon displays agent
status, recent findings, and provides quick actions (open dashboard, pause /
resume, quit).  Native macOS notifications are dispatched for CRITICAL and HIGH
findings with per-severity rate limiting.

Must run on the main thread (macOS AppKit constraint).
"""

from __future__ import annotations

import collections
import logging
import os
import time
import webbrowser
from typing import Any, Callable

logger = logging.getLogger(__name__)

try:
    import rumps
except ImportError:
    rumps = None  # type: ignore[assignment]

# ── Embedded menu bar icons (12×12 PNG circles) ─────────────────────────
# Generated as minimal 12×12 PNG images — avoids a Pillow dependency.

def _make_circle_png(r: int, g: int, b: int) -> bytes:
    """Generate a tiny 12×12 PNG with a filled circle of the given colour."""
    import struct
    import zlib

    size = 12
    # Build RGBA rows (filter byte 0 + 4 bytes per pixel)
    rows = bytearray()
    cx, cy = size / 2 - 0.5, size / 2 - 0.5
    radius = size / 2 - 1
    for y in range(size):
        rows.append(0)  # filter: none
        for x in range(size):
            dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if dist <= radius:
                rows.extend([r, g, b, 255])
            elif dist <= radius + 1:
                # Anti-alias fringe
                alpha = max(0, min(255, int(255 * (radius + 1 - dist))))
                rows.extend([r, g, b, alpha])
            else:
                rows.extend([0, 0, 0, 0])

    def _chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(rows))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


# Pre-built icon data
_ICON_GREEN = _make_circle_png(34, 197, 94)   # #22c55e — healthy
_ICON_ORANGE = _make_circle_png(249, 115, 22)  # #f97316 — HIGH findings
_ICON_RED = _make_circle_png(239, 68, 68)     # #ef4444 — CRITICAL findings
_ICON_GRAY = _make_circle_png(156, 163, 175)  # #9ca3af — stopped / unhealthy


def _icon_path(data: bytes, name: str) -> str:
    """Write icon bytes to a temp file and return the path.

    rumps needs a file path, not raw bytes.
    """
    import tempfile
    fd, path = tempfile.mkstemp(prefix=f"edr_icon_{name}_", suffix=".png")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


class EDRTrayApp:
    """macOS menu bar tray icon backed by rumps."""

    def __init__(
        self,
        dashboard_port: int = 9200,
        notification_cooldown: int = 60,
        notify_on_high: bool = True,
        notify_on_critical: bool = True,
        shutdown_callback: Callable[[], None] | None = None,
        pause_callback: Callable[[bool], None] | None = None,
        status_callback: Callable[[], dict[str, Any]] | None = None,
    ):
        if rumps is None:
            raise ImportError("rumps is required for the macOS tray icon")

        self._dashboard_port = dashboard_port
        self._notification_cooldown = notification_cooldown
        self._notify_on_high = notify_on_high
        self._notify_on_critical = notify_on_critical
        self._shutdown_callback = shutdown_callback
        self._pause_callback = pause_callback
        self._status_callback = status_callback

        # Rate limiting: {severity: last_notification_timestamp}
        self._last_notification: dict[str, float] = {}

        # Notification queue (thread-safe) — findings pushed by analyzer thread
        self.notification_queue: collections.deque = collections.deque(maxlen=100)

        # Icon file paths (written once at startup)
        self._icon_paths = {
            "green": _icon_path(_ICON_GREEN, "green"),
            "orange": _icon_path(_ICON_ORANGE, "orange"),
            "red": _icon_path(_ICON_RED, "red"),
            "gray": _icon_path(_ICON_GRAY, "gray"),
        }

        # Build the rumps app
        self._app = rumps.App(
            "EDR Graph Agent",
            icon=self._icon_paths["green"],
            quit_button=None,  # We'll add our own quit
        )

        # Menu items (stored for dynamic updates)
        self._status_item = rumps.MenuItem("Status: Starting...")
        self._events_item = rumps.MenuItem("Events: —")
        self._findings_item = rumps.MenuItem("Findings: —")
        self._last_alert_item = rumps.MenuItem("Last Alert: None")
        self._open_dashboard = rumps.MenuItem(
            "Open Dashboard", callback=self._on_open_dashboard, key="d"
        )

        # Collector submenu
        self._collectors_menu = rumps.MenuItem("Collectors")

        # Pause / Resume
        self._pause_item = rumps.MenuItem("Pause Agent", callback=self._on_pause)
        self._resume_item = rumps.MenuItem("Resume Agent", callback=self._on_resume)

        # Quit
        self._quit_item = rumps.MenuItem("Quit", callback=self._on_quit)

        self._app.menu = [
            self._status_item,
            self._events_item,
            None,  # separator
            self._findings_item,
            self._last_alert_item,
            None,
            self._open_dashboard,
            None,
            self._collectors_menu,
            None,
            self._pause_item,
            self._resume_item,
            None,
            self._quit_item,
        ]

        # State
        self._paused = False
        self._current_icon = "green"

        # Timer for periodic updates (every 2 seconds)
        self._timer = rumps.Timer(self._on_timer, 2)

    def run(self) -> None:
        """Start the tray icon event loop (blocks the main thread)."""
        self._timer.start()
        self._app.run()

    def push_finding(self, finding: Any) -> None:
        """Push a finding to the notification queue (thread-safe)."""
        self.notification_queue.appendleft({
            "severity": getattr(finding, "severity", "MEDIUM"),
            "title": getattr(finding, "title", "Finding"),
            "id": getattr(finding, "id", ""),
            "timestamp": time.time(),
        })

    # ── Menu callbacks ──────────────────────────────────────────────────

    def _on_open_dashboard(self, _sender: Any) -> None:
        webbrowser.open(f"http://127.0.0.1:{self._dashboard_port}")

    def _on_pause(self, _sender: Any) -> None:
        self._paused = True
        if self._pause_callback:
            self._pause_callback(True)
        self._status_item.title = "Status: Paused"
        logger.info("Agent paused via tray icon")

    def _on_resume(self, _sender: Any) -> None:
        self._paused = False
        if self._pause_callback:
            self._pause_callback(False)
        self._status_item.title = "Status: Running"
        logger.info("Agent resumed via tray icon")

    def _on_quit(self, _sender: Any) -> None:
        logger.info("Quit requested via tray icon")
        if self._shutdown_callback:
            self._shutdown_callback()
        rumps.quit_application()

    # ── Timer callback (runs every 2s on main thread) ───────────────────

    def _on_timer(self, _timer: Any) -> None:
        """Periodic update: refresh status menu items, dispatch notifications."""
        try:
            self._update_status()
            self._dispatch_notifications()
        except Exception:
            logger.debug("Tray timer update failed", exc_info=True)

    def _update_status(self) -> None:
        """Refresh menu items from agent status."""
        if not self._status_callback:
            return

        try:
            status = self._status_callback()
        except Exception:
            self._set_icon("gray")
            self._status_item.title = "Status: Error"
            return

        if not status:
            return

        # Status line with uptime
        agent_status = status.get("agent_status", "unknown")
        uptime = status.get("uptime_seconds", 0)
        uptime_str = _format_uptime(uptime)

        if self._paused:
            self._status_item.title = f"Status: Paused ({uptime_str} uptime)"
        else:
            self._status_item.title = f"Status: {agent_status.title()} ({uptime_str} uptime)"

        # Events
        processed = status.get("events_processed", 0)
        eps = status.get("events_per_second", 0)
        self._events_item.title = f"Events: {processed:,} processed ({eps}/sec)"

        # Findings summary
        findings_total = status.get("findings_total", 0)
        findings_high = status.get("findings_high", 0)
        findings_critical = status.get("findings_critical", 0)
        last_title = status.get("last_finding_title")
        self.update_findings_summary(
            findings_total, findings_high, findings_critical, last_title
        )

        # Collectors
        collectors = status.get("collector_sources", [])
        if collectors:
            # Clear and rebuild submenu
            keys_to_remove = list(self._collectors_menu.keys())
            for k in keys_to_remove:
                del self._collectors_menu[k]
            for name in collectors:
                self._collectors_menu[name] = rumps.MenuItem(f"\u2713 {name}")

    def _dispatch_notifications(self) -> None:
        """Check the notification queue and send macOS notifications."""
        now = time.time()
        batch: list[dict] = []

        # Drain the queue
        while self.notification_queue:
            try:
                batch.append(self.notification_queue.pop())
            except IndexError:
                break

        for item in batch:
            severity = item.get("severity", "MEDIUM")
            title = item.get("title", "Finding")

            # Only notify for CRITICAL and HIGH
            if severity == "CRITICAL" and not self._notify_on_critical:
                continue
            if severity == "HIGH" and not self._notify_on_high:
                continue
            if severity not in ("CRITICAL", "HIGH"):
                continue

            # Rate limit: max 1 per severity per cooldown period
            last = self._last_notification.get(severity, 0)
            if now - last < self._notification_cooldown:
                continue

            self._last_notification[severity] = now

            # Send macOS notification
            sound = severity == "CRITICAL"
            rumps.notification(
                title=f"EDR {severity} Alert",
                subtitle="",
                message=title,
                sound=sound,
            )
            logger.info("Sent %s notification: %s", severity, title)

        # Update icon and findings count based on recent notifications
        self._update_icon_from_findings()

    def _update_icon_from_findings(self) -> None:
        """Set the tray icon colour based on recent finding severity."""
        if not self._status_callback:
            return

        now = time.time()
        one_hour_ago = now - 3600

        # Check if we had recent CRITICAL or HIGH notifications
        has_critical = (
            self._last_notification.get("CRITICAL", 0) > one_hour_ago
        )
        has_high = (
            self._last_notification.get("HIGH", 0) > one_hour_ago
        )

        if has_critical:
            self._set_icon("red")
        elif has_high:
            self._set_icon("orange")
        elif self._paused:
            self._set_icon("gray")
        else:
            self._set_icon("green")

    def _set_icon(self, color: str) -> None:
        """Update the menu bar icon if it changed."""
        if color != self._current_icon:
            self._current_icon = color
            self._app.icon = self._icon_paths.get(color, self._icon_paths["green"])

    # ── Findings summary update ─────────────────────────────────────────

    def update_findings_summary(
        self, total: int, high: int, critical: int, last_title: str | None = None
    ) -> None:
        """Update the findings menu items (called from background thread via timer)."""
        parts = [f"{total} total"]
        if high:
            parts.append(f"{high} HIGH")
        if critical:
            parts.append(f"{critical} CRITICAL")
        self._findings_item.title = f"Findings: {', '.join(parts)}"

        if last_title:
            self._last_alert_item.title = f"Last Alert: {last_title}"


def _format_uptime(seconds: float) -> str:
    """Format seconds into a human-readable uptime string."""
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
