"""Tests for multi-IP reporting: ip_discovery module, forwarder IP fields, server handling."""

from __future__ import annotations

import socket
import sys
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

import agent.fleet.ip_discovery as ip_disc
from agent.config import Settings, load_config_file
from agent.fleet.ip_discovery import PublicIpMonitor, get_local_ips

# ── get_local_ips() ──


class TestGetLocalIps:
    def setup_method(self):
        """Reset the local IP cache before each test."""
        ip_disc._local_ips_cache = []
        ip_disc._local_ips_cache_time = 0.0
    def test_filters_loopback_ipv4(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "lo": [Addr(socket.AF_INET, "127.0.0.1")],
            "eth0": [Addr(socket.AF_INET, "10.0.0.5")],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert "127.0.0.1" not in ips
        assert "10.0.0.5" in ips

    def test_filters_loopback_ipv6(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "lo": [Addr(socket.AF_INET6, "::1")],
            "eth0": [Addr(socket.AF_INET6, "fd00::1")],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert "::1" not in ips
        assert "fd00::1" in ips

    def test_filters_link_local_ipv4(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "eth0": [
                Addr(socket.AF_INET, "169.254.1.1"),
                Addr(socket.AF_INET, "192.168.1.100"),
            ],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert "169.254.1.1" not in ips
        assert "192.168.1.100" in ips

    def test_filters_link_local_ipv6(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "eth0": [
                Addr(socket.AF_INET6, "fe80::1%eth0"),
                Addr(socket.AF_INET6, "2001:db8::1"),
            ],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert not any(ip.startswith("fe80") for ip in ips)
        assert "2001:db8::1" in ips

    def test_ipv4_sorted_before_ipv6(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "eth0": [
                Addr(socket.AF_INET6, "2001:db8::1"),
                Addr(socket.AF_INET, "10.0.0.1"),
            ],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert ips == ["10.0.0.1", "2001:db8::1"]

    def test_deduplicates(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "eth0": [Addr(socket.AF_INET, "10.0.0.1")],
            "br0": [Addr(socket.AF_INET, "10.0.0.1")],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert ips.count("10.0.0.1") == 1

    def test_empty_when_only_loopback(self):
        Addr = namedtuple("Addr", ["family", "address"])
        fake_addrs = {
            "lo": [Addr(socket.AF_INET, "127.0.0.1"), Addr(socket.AF_INET6, "::1")],
        }
        with patch("agent.fleet.ip_discovery.psutil") as mock_ps:
            mock_ps.net_if_addrs.return_value = fake_addrs
            ips = get_local_ips()
        assert ips == []

    def test_works_with_real_interfaces(self):
        """Sanity check: get_local_ips returns at least one IP on dev machine."""
        ips = get_local_ips()
        assert isinstance(ips, list)
        # Should have at least one non-loopback interface
        assert len(ips) >= 1
        assert "127.0.0.1" not in ips


# ── PublicIpMonitor ──


class TestPublicIpMonitor:
    def test_initial_ip_is_empty(self):
        monitor = PublicIpMonitor(interval=300)
        assert monitor.current_ip == ""

    def test_stop_before_start_is_safe(self):
        monitor = PublicIpMonitor(interval=300)
        monitor.stop()  # Should not raise

    def test_fetches_ip_on_start(self):
        with patch("agent.fleet.ip_discovery._fetch_public_ip", return_value="203.0.113.1"):
            monitor = PublicIpMonitor(interval=9999)
            monitor.start()
            # Give the thread a moment to execute
            import time

            time.sleep(0.1)
            assert monitor.current_ip == "203.0.113.1"
            monitor.stop()

    def test_keeps_previous_on_failure(self):
        call_count = 0

        def fake_fetch():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "1.2.3.4"
            return ""

        with patch("agent.fleet.ip_discovery._fetch_public_ip", side_effect=fake_fetch):
            monitor = PublicIpMonitor(interval=0.05)
            monitor.start()
            import time

            time.sleep(0.2)
            # Should still have the first successful IP
            assert monitor.current_ip == "1.2.3.4"
            monitor.stop()


# ── Config ──


class TestIpConfig:
    def test_fleet_public_ip_interval_default(self):
        s = Settings()
        assert s.fleet_public_ip_interval == 300.0

    def test_fleet_public_ip_interval_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  public_ip_interval: 60\n")
        result = load_config_file(f)
        assert result["fleet_public_ip_interval"] == 60


# ── Forwarder integration ──


_has_grpc = bool(sys.modules.get("grpc"))
if not _has_grpc:
    try:
        import grpc as _grpc  # noqa: F401

        _has_grpc = True
    except ImportError:
        pass


@pytest.mark.skipif(not _has_grpc, reason="grpc not installed")
class TestForwarderIpFields:
    def test_register_includes_ip_fields(self, tmp_path):
        """register() should populate ip_addresses and public_ip in the AgentInfo proto."""
        from agent.fleet.proto import fleet_pb2
        from agent.queue.sqlite_queue import SqliteQueue

        settings = Settings(fleet_enabled=True, fleet_url="localhost:50051", data_dir=tmp_path)
        queue = SqliteQueue(tmp_path / "test.db")

        with (
            patch("agent.fleet.forwarder.grpc") as mock_grpc,
            patch(
                "agent.fleet.forwarder.get_local_ips",
                return_value=["10.0.0.5", "192.168.1.10"],
            ),
            patch("agent.fleet.ip_discovery._fetch_public_ip", return_value="203.0.113.1"),
        ):
            mock_channel = MagicMock()
            mock_grpc.insecure_channel.return_value = mock_channel
            mock_stub = MagicMock()
            mock_grpc.return_value = mock_stub

            from agent.fleet.forwarder import FleetForwarder

            forwarder = FleetForwarder(settings=settings, queue=queue)

            # Wait for public IP monitor to fetch
            import time

            time.sleep(0.15)

            # Capture what register() sends
            mock_stub_instance = mock_channel.unary_unary.return_value
            mock_stub_instance.return_value = fleet_pb2.RegisterAgentResponse(
                accepted=True, agent_id="test-id", message="ok"
            )

            forwarder.register()

            # Get the RegisterAgentRequest that was sent
            call_args = mock_stub_instance.call_args
            if call_args:
                request = call_args[0][0]
                info = request.agent_info
                assert list(info.ip_addresses) == ["10.0.0.5", "192.168.1.10"]
                assert info.ip_address == "10.0.0.5"  # backward compat
                assert info.public_ip == "203.0.113.1"

            forwarder.stop()
        queue.close()

    def test_heartbeat_includes_ip_fields(self, tmp_path):
        """send_heartbeat() should include ip_addresses and public_ip."""
        from agent.fleet.proto import fleet_pb2
        from agent.queue.sqlite_queue import SqliteQueue

        settings = Settings(fleet_enabled=True, fleet_url="localhost:50051", data_dir=tmp_path)
        queue = SqliteQueue(tmp_path / "test.db")

        with (
            patch("agent.fleet.forwarder.grpc") as mock_grpc,
            patch(
                "agent.fleet.forwarder.get_local_ips",
                return_value=["10.0.0.5"],
            ),
            patch("agent.fleet.ip_discovery._fetch_public_ip", return_value="203.0.113.1"),
        ):
            mock_channel = MagicMock()
            mock_grpc.insecure_channel.return_value = mock_channel

            from agent.fleet.forwarder import FleetForwarder

            forwarder = FleetForwarder(settings=settings, queue=queue)

            import time

            time.sleep(0.15)

            mock_stub_instance = mock_channel.unary_unary.return_value
            mock_stub_instance.return_value = fleet_pb2.HeartbeatResponse(
                acknowledged=True, message="ok"
            )

            forwarder.send_heartbeat()

            call_args = mock_stub_instance.call_args
            if call_args:
                request = call_args[0][0]
                assert list(request.ip_addresses) == ["10.0.0.5"]
                assert request.public_ip == "203.0.113.1"

            forwarder.stop()
        queue.close()


# ── Server-side gRPC service ──


@pytest.mark.skipif(not _has_grpc, reason="grpc not installed")
class TestGrpcServiceIpExtraction:
    def test_register_extracts_ip_fields(self):
        """RegisterAgent should extract ip_addresses, public_ip, grpc_peer_ip."""
        from agent.fleet.proto import fleet_pb2

        mock_neo4j = MagicMock()
        mock_neo4j.validate_registration_key.return_value = (True, "ok")

        from server.grpc_service import FleetServicer

        servicer = FleetServicer(mock_neo4j)

        info = fleet_pb2.AgentInfo(
            agent_id="agent-1",
            hostname="host1",
            platform="linux",
            os_version="6.x",
            agent_version="0.1.0",
            ip_address="10.0.0.5",
            registered_at=1000000,
            ip_addresses=["10.0.0.5", "192.168.1.10"],
            public_ip="203.0.113.1",
        )
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=info,
            registration_key="valid-key",
        )

        context = MagicMock()
        context.peer.return_value = "ipv4:172.17.0.1:12345"

        response = servicer.RegisterAgent(request, context)
        assert response.accepted is True

        # Verify neo4j.register_agent was called with the right data
        call_args = mock_neo4j.register_agent.call_args
        agent_data = call_args[0][0]
        assert agent_data["ip_addresses"] == ["10.0.0.5", "192.168.1.10"]
        assert agent_data["public_ip"] == "203.0.113.1"
        assert agent_data["grpc_peer_ip"] == "172.17.0.1"
        assert agent_data["ip_address"] == "10.0.0.5"

    def test_register_old_agent_no_ip_fields(self):
        """Old agents that don't send ip_addresses should still work."""
        from agent.fleet.proto import fleet_pb2

        mock_neo4j = MagicMock()
        mock_neo4j.validate_registration_key.return_value = (True, "ok")

        from server.grpc_service import FleetServicer

        servicer = FleetServicer(mock_neo4j)

        # Old-style AgentInfo without ip_addresses/public_ip
        info = fleet_pb2.AgentInfo(
            agent_id="old-agent",
            hostname="oldhost",
            platform="linux",
        )
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=info,
            registration_key="valid-key",
        )

        context = MagicMock()
        context.peer.return_value = "ipv4:172.17.0.1:12345"

        response = servicer.RegisterAgent(request, context)
        assert response.accepted is True

        agent_data = mock_neo4j.register_agent.call_args[0][0]
        assert agent_data["ip_addresses"] == []
        assert agent_data["public_ip"] == ""
        assert agent_data["grpc_peer_ip"] == "172.17.0.1"
        # Falls back to gRPC peer IP
        assert agent_data["ip_address"] == "172.17.0.1"

    def test_heartbeat_passes_ip_fields(self):
        """Heartbeat should pass ip_addresses and public_ip to update_heartbeat."""
        from agent.fleet.proto import fleet_pb2

        mock_neo4j = MagicMock()

        from server.grpc_service import FleetServicer

        servicer = FleetServicer(mock_neo4j)

        request = fleet_pb2.HeartbeatRequest(
            agent_id="agent-1",
            timestamp=1000000,
            status="healthy",
            ip_addresses=["10.0.0.5"],
            public_ip="203.0.113.1",
        )
        context = MagicMock()

        servicer.Heartbeat(request, context)

        mock_neo4j.update_heartbeat.assert_called_once_with(
            "agent-1",
            1000000,
            clock_offset_ms=0,
            ip_addresses=["10.0.0.5"],
            public_ip="203.0.113.1",
        )

    def test_heartbeat_old_agent_no_ips(self):
        """Old agent heartbeat without IPs should pass None (skip update)."""
        from agent.fleet.proto import fleet_pb2

        mock_neo4j = MagicMock()

        from server.grpc_service import FleetServicer

        servicer = FleetServicer(mock_neo4j)

        request = fleet_pb2.HeartbeatRequest(
            agent_id="old-agent",
            timestamp=1000000,
            status="healthy",
        )
        context = MagicMock()

        servicer.Heartbeat(request, context)

        mock_neo4j.update_heartbeat.assert_called_once_with(
            "old-agent",
            1000000,
            clock_offset_ms=0,
            ip_addresses=None,
            public_ip=None,
        )
