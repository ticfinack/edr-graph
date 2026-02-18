"""Tests for listening port mapper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent.enrichment.port_mapper import (
    ConnectionContext,
    ListeningService,
    PortMapper,
)
from agent.enrichment.process_identity import ProcessIdentity


class TestPortMapper:
    def test_get_listener_exact_match(self):
        """Exact IP:port match should work."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("127.0.0.1", 8080): ListeningService(
                port=8080,
                protocol="tcp",
                pid=100,
                process_name="nginx",
                bind_address="127.0.0.1",
            ),
        }
        mapper._last_refresh = 1e18  # skip refresh

        svc = mapper.get_listener("127.0.0.1", 8080)
        assert svc is not None
        assert svc.process_name == "nginx"
        assert svc.pid == 100

    def test_wildcard_fallback(self):
        """Wildcard 0.0.0.0 should match 127.0.0.1 queries."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("0.0.0.0", 3000): ListeningService(
                port=3000,
                protocol="tcp",
                pid=200,
                process_name="node",
                bind_address="0.0.0.0",
            ),
        }
        mapper._last_refresh = 1e18

        # Query for 127.0.0.1:3000 should fall back to 0.0.0.0
        svc = mapper.get_listener("127.0.0.1", 3000)
        assert svc is not None
        assert svc.process_name == "node"

    def test_ipv6_wildcard_fallback(self):
        """IPv6 wildcard :: should also be checked."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("::", 5000): ListeningService(
                port=5000,
                protocol="tcp",
                pid=300,
                process_name="flask",
                bind_address="::",
            ),
        }
        mapper._last_refresh = 1e18

        svc = mapper.get_listener("::1", 5000)
        assert svc is not None
        assert svc.process_name == "flask"

    def test_no_match_returns_none(self):
        """Unknown port should return None."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {}
        mapper._last_refresh = 1e18

        svc = mapper.get_listener("1.2.3.4", 9999)
        assert svc is None


class TestConnectionContext:
    def test_localhost_ipc_detection(self):
        """Connections to 127.0.0.1 should be detected as localhost IPC."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("0.0.0.0", 62874): ListeningService(
                port=62874,
                protocol="tcp",
                pid=500,
                process_name="com.docker.backend",
                bind_address="0.0.0.0",
                identity=ProcessIdentity(
                    pid=500,
                    path="/usr/local/bin/docker",
                    name="docker",
                    code_signed=True,
                    signing_authority="Developer ID Application: Docker Inc",
                ),
            ),
        }
        mapper._last_refresh = 1e18

        src_identity = ProcessIdentity(
            pid=400,
            path="/Applications/OrbStack.app/Contents/Helpers/orbhelper",
            name="OrbStack Helper",
            code_signed=True,
            signing_authority="Developer ID Application: Khanh Dong Nguyen",
        )

        ctx = mapper.build_connection_context(
            src_pid=400,
            src_name="OrbStack Helper",
            src_identity=src_identity,
            dst_ip="127.0.0.1",
            dst_port=62874,
        )

        assert ctx.is_localhost_ipc is True
        assert ctx.is_known_app_to_known_app is True
        assert ctx.dest_process == "com.docker.backend"
        assert ctx.dest_pid == 500
        assert "Localhost IPC" in ctx.connection_description
        assert "both signed" in ctx.connection_description

    def test_external_connection(self):
        """Connections to external IPs should not be localhost IPC."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {}
        mapper._last_refresh = 1e18

        ctx = mapper.build_connection_context(
            src_pid=100,
            src_name="curl",
            src_identity=None,
            dst_ip="93.184.216.34",
            dst_port=443,
        )

        assert ctx.is_localhost_ipc is False
        assert ctx.is_known_app_to_known_app is False
        assert "External connection" in ctx.connection_description

    def test_unknown_listener_on_localhost(self):
        """Connection to localhost with no known listener."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {}
        mapper._last_refresh = 1e18

        ctx = mapper.build_connection_context(
            src_pid=100,
            src_name="unknown_app",
            src_identity=None,
            dst_ip="127.0.0.1",
            dst_port=31337,
        )

        assert ctx.is_localhost_ipc is True
        assert ctx.dest_process is None
        assert ctx.is_known_app_to_known_app is False

    def test_known_app_to_known_app(self):
        """Both sides code-signed should set is_known_app_to_known_app."""
        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("127.0.0.1", 5000): ListeningService(
                port=5000,
                protocol="tcp",
                pid=200,
                process_name="server_app",
                bind_address="127.0.0.1",
                identity=ProcessIdentity(code_signed=True),
            ),
        }
        mapper._last_refresh = 1e18

        src_identity = ProcessIdentity(code_signed=True)
        ctx = mapper.build_connection_context(
            src_pid=100,
            src_name="client_app",
            src_identity=src_identity,
            dst_ip="127.0.0.1",
            dst_port=5000,
        )

        assert ctx.is_known_app_to_known_app is True

    @pytest.mark.skipif(True, reason="Requires root for psutil.net_connections")
    def test_refresh_finds_listeners(self):
        """Live test: refresh should find at least one listener."""
        mapper = PortMapper(refresh_interval=0)
        mapper.refresh()
        assert len(mapper._port_map) > 0


class TestEntityExtractorPortMapper:
    """Test port mapper integration in entity_extractor."""

    def test_port_mapper_adds_risk_indicator(self):
        from datetime import datetime

        from agent.processor.entity_extractor import extract_entities
        from agent.schema.ocsf_types import (
            DeviceInfo,
            NetworkActivity,
            NetworkEndpoint,
            ProcessInfo,
        )

        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("0.0.0.0", 8080): ListeningService(
                port=8080,
                protocol="tcp",
                pid=500,
                process_name="node",
                bind_address="0.0.0.0",
            ),
        }
        mapper._last_refresh = 1e18

        event = NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(
                pid=100,
                name="curl",
                cmd_line="curl localhost:8080",
                exe_path="/usr/bin/curl",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
            dst_endpoint=NetworkEndpoint(ip="127.0.0.1", port=8080),
        )

        entities = extract_entities(event, event_id=1, port_mapper=mapper)
        # Should have a connection_context risk indicator
        ctx_indicators = [
            r for r in entities.risk_indicators
            if r.get("type") == "connection_context"
        ]
        assert len(ctx_indicators) == 1
        assert "Localhost IPC" in ctx_indicators[0]["description"]
        assert "node" in ctx_indicators[0]["description"]
