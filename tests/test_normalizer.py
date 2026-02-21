"""Tests for the normalization pipeline."""

from datetime import datetime

from agent.collectors.base import RawEvent
from agent.normalizer import normalize
from agent.schema.ocsf_types import Authentication, NetworkActivity, ProcessActivity


class TestProcessNormalization:
    def test_psutil_process(self):
        raw = RawEvent(
            timestamp=datetime(2025, 1, 15, 10, 0),
            source="psutil_process",
            message="New process: curl (PID 1234)",
            fields={
                "pid": "1234",
                "name": "curl",
                "username": "alice",
                "cmdline": "curl https://example.com",
                "exe": "/usr/bin/curl",
                "ppid": "100",
                "create_time": "2025-01-15T10:00:00",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, ProcessActivity)
        assert result.class_uid == 1007
        assert result.process.pid == 1234
        assert result.process.name == "curl"
        assert result.actor.user.name == "alice"
        assert result.process.cmd_line == "curl https://example.com"

    def test_missing_username(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="psutil_process",
            message="New process: init",
            fields={"pid": "1", "name": "init"},
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, ProcessActivity)
        assert result.actor is None

    def test_empty_name_returns_none(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="psutil_process",
            message="",
            fields={"pid": "0"},
            hostname="testhost",
        )
        result = normalize(raw)
        assert result is None

    def test_unified_log_with_image_path(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="unified_log",
            message="some log message",
            fields={
                "name": "syslogd",
                "process": "/usr/sbin/syslogd",
                "pid": "100",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, ProcessActivity)
        assert result.process.name == "syslogd"

    def test_name_from_exe_path_fallback(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="psutil_process",
            message="",
            fields={"pid": "999", "exe": "/usr/bin/wget"},
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, ProcessActivity)
        assert result.process.name == "wget"


class TestNetworkNormalization:
    def test_psutil_network(self):
        raw = RawEvent(
            timestamp=datetime(2025, 1, 15, 10, 0),
            source="psutil_network",
            message="New connection: curl -> 93.184.216.34:443",
            fields={
                "pid": "1234",
                "process_name": "curl",
                "src_ip": "192.168.1.100",
                "src_port": "54321",
                "dst_ip": "93.184.216.34",
                "dst_port": "443",
                "status": "ESTABLISHED",
                "type": "TCP",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, NetworkActivity)
        assert result.class_uid == 4001
        assert result.dst_endpoint.ip == "93.184.216.34"
        assert result.dst_endpoint.port == 443
        assert result.process.name == "curl"

    def test_ebpf_network(self):
        """source='ebpf_network' produces NetworkActivity with correct log_source."""
        raw = RawEvent(
            timestamp=datetime(2025, 1, 15, 10, 0),
            source="ebpf_network",
            message="connect: curl -> 93.184.216.34:443",
            fields={
                "pid": "5678",
                "process_name": "curl",
                "src_ip": "192.168.1.10",
                "src_port": "0",
                "dst_ip": "93.184.216.34",
                "dst_port": "443",
                "status": "ESTABLISHED",
                "type": "TCP",
                "uid": "1000",
                "username": "alice",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, NetworkActivity)
        assert result.class_uid == 4001
        assert result.dst_endpoint.ip == "93.184.216.34"
        assert result.dst_endpoint.port == 443
        assert result.process.name == "curl"
        assert result.metadata.log_source == "ebpf_network"


class TestAuthNormalization:
    def test_successful_login(self):
        raw = RawEvent(
            timestamp=datetime(2025, 1, 15, 10, 0),
            source="auth",
            message="Accepted password for alice from 10.0.0.1 port 22 ssh2",
            fields={},
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, Authentication)
        assert result.class_uid == 3002
        assert result.activity_id == 1  # Logon
        assert result.status_id == 1  # Success
        assert result.user.name == "alice"
        assert result.src_endpoint.ip == "10.0.0.1"

    def test_failed_login(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="auth",
            message="Failed password for bob from 192.168.1.50 port 22 ssh2",
            fields={},
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, Authentication)
        assert result.status_id == 2  # Failure
        assert result.user.name == "bob"

    def test_unknown_source_returns_none(self):
        raw = RawEvent(
            timestamp=datetime.now(),
            source="unknown_source_xyz",
            message="Something",
            fields={},
            hostname="testhost",
        )
        result = normalize(raw)
        assert result is None
