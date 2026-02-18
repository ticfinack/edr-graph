"""Lightweight HTTP server for /health and /metrics endpoints."""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from agent.metrics import agent_uptime, queue_depth

logger = logging.getLogger(__name__)


class _HealthHandler(BaseHTTPRequestHandler):
    """Handles GET /health and GET /metrics."""

    # Set by start_health_server
    _start_time: float = 0.0
    _queue_getter = None  # callable returning int

    def do_GET(self) -> None:
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/metrics":
            self._handle_metrics()
        else:
            self.send_error(404)

    def _handle_health(self) -> None:
        uptime = time.monotonic() - self._start_time
        q_depth = self._queue_getter() if self._queue_getter else 0
        body = json.dumps({
            "status": "healthy",
            "uptime_seconds": round(uptime, 1),
            "queue_depth": q_depth,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_metrics(self) -> None:
        # Update gauges before generating output
        uptime = time.monotonic() - self._start_time
        agent_uptime.set(uptime)
        if self._queue_getter:
            queue_depth.set(self._queue_getter())

        body = generate_latest()
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE_LATEST)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        # Suppress default access log noise
        pass


def start_health_server(
    port: int = 9100,
    queue_depth_fn=None,
) -> HTTPServer:
    """Start the health/metrics HTTP server on a daemon thread.

    Args:
        port: TCP port to bind (localhost only).
        queue_depth_fn: Callable returning current queue depth (int).

    Returns:
        The HTTPServer instance (for testing or shutdown).
    """
    _HealthHandler._start_time = time.monotonic()
    _HealthHandler._queue_getter = staticmethod(queue_depth_fn) if queue_depth_fn else None

    server = HTTPServer(("127.0.0.1", port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="health")
    thread.start()
    logger.info("Health/metrics server started on http://127.0.0.1:%d", port)
    return server
