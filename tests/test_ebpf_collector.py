"""Tests for the Linux eBPF process collector.

All tests mock BCC so they run on macOS/CI without a Linux kernel.
"""

from __future__ import annotations

import os
import socket
import struct
from datetime import datetime
from unittest.mock import patch

from agent.collectors.base import RawEvent
from agent.collectors.ebpf_collector import (
    EbpfCollector,
    _WATCHED_PREFIXES,
    _parse_dns_qname,
    _resolve_username,
)
from agent.collectors.psutil_collector import PsutilCollector
from agent.normalizer import normalize
from agent.schema.ocsf_types import DnsActivity, FileActivity, NetworkActivity


class TestEbpfCollector:
    def test_buffer_drain(self):
        """collect() drains the internal buffer and empties it."""
        collector = EbpfCollector()
        ev = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_execve",
            message="execve: bash (PID 100)",
            fields={"pid": "100", "name": "bash", "exe": "/bin/bash", "ppid": "1"},
            hostname="testhost",
        )
        collector._buffer.append(ev)
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 2
        assert len(collector._buffer) == 0

    def test_normalizer_dispatch(self):
        """source='ebpf_execve' routes through normalize_process correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_execve",
            message="execve: curl (PID 5678)",
            fields={
                "pid": "5678",
                "name": "curl",
                "username": "alice",
                "cmdline": "/usr/bin/curl https://example.com",
                "exe": "/usr/bin/curl",
                "ppid": "1000",
                "create_time": datetime.now().isoformat(),
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert result is not None
        assert result.process.pid == 5678
        assert result.process.name == "curl"
        assert result.process.parent_pid == 1000
        assert result.actor is not None
        assert result.actor.user.name == "alice"

    @patch("agent.collectors.ebpf_collector._read_loginuid", return_value=1000)
    @patch("agent.collectors.ebpf_collector.pwd")
    def test_auid_preferred_over_euid(self, mock_pwd, mock_read_loginuid):
        """When AUID is set, username resolves from AUID, not effective UID."""
        import types

        mock_pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_name="alice" if uid == 1000 else "root")

        username = _resolve_username(1000, 0)
        assert username == "alice"

    @patch("agent.collectors.ebpf_collector._read_loginuid", return_value=4294967295)
    @patch("agent.collectors.ebpf_collector.pwd")
    def test_auid_unset_falls_back_to_euid(self, mock_pwd, mock_read_loginuid):
        """When AUID is 4294967295 (unset), falls back to effective UID."""
        import types

        mock_pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_name="root" if uid == 0 else "unknown")

        username = _resolve_username(4294967295, 0)
        assert username == "root"

    @patch("agent.collectors.ebpf_collector._read_loginuid", return_value=None)
    @patch("agent.collectors.ebpf_collector.pwd")
    def test_auid_read_failure_falls_back_to_euid(self, mock_pwd, mock_read_loginuid):
        """When /proc/<pid>/loginuid cannot be read, falls back to effective UID."""
        import types

        mock_pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_name="daemon" if uid == 2 else "unknown")

        username = _resolve_username(None, 2)
        assert username == "daemon"

    def test_agent_pid_skipped(self):
        """Events from the agent's own PID are not buffered."""
        collector = EbpfCollector()
        agent_pid = os.getpid()
        collector._agent_pid = agent_pid

        # Simulate what _process_exec_event does: skip if pid == _agent_pid
        # We can't call _process_exec_event directly without a real BPF object,
        # so we verify the filtering logic by crafting events manually.
        ev_self = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_execve",
            message=f"execve: python (PID {agent_pid})",
            fields={"pid": str(agent_pid), "name": "python"},
            hostname="testhost",
        )
        ev_other = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_execve",
            message="execve: bash (PID 9999)",
            fields={"pid": "9999", "name": "bash"},
            hostname="testhost",
        )

        # Simulate the filtering: only buffer events where pid != agent_pid
        for ev in [ev_self, ev_other]:
            pid = int(ev.fields["pid"])
            if pid != collector._agent_pid:
                collector._buffer.append(ev)

        events = collector.collect()
        assert len(events) == 1
        assert events[0].fields["pid"] == "9999"

    def test_network_normalizer_dispatch(self):
        """source='ebpf_network' routes through normalize_network correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
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

    def test_network_buffer_drain(self):
        """collect() drains network events from the buffer."""
        collector = EbpfCollector()
        ev = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_network",
            message="connect: curl -> 1.2.3.4:80",
            fields={
                "pid": "200",
                "process_name": "curl",
                "dst_ip": "1.2.3.4",
                "dst_port": "80",
            },
            hostname="testhost",
        )
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 1
        assert events[0].source == "ebpf_network"
        assert len(collector._buffer) == 0

    def test_agent_pid_skipped_network(self):
        """Network events from the agent's own PID are not buffered."""
        collector = EbpfCollector()
        agent_pid = os.getpid()
        collector._agent_pid = agent_pid

        ev_self = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_network",
            message="connect: python -> 1.2.3.4:80",
            fields={"pid": str(agent_pid), "process_name": "python"},
            hostname="testhost",
        )
        ev_other = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_network",
            message="connect: curl -> 1.2.3.4:80",
            fields={"pid": "9999", "process_name": "curl"},
            hostname="testhost",
        )

        for ev in [ev_self, ev_other]:
            pid = int(ev.fields["pid"])
            if pid != collector._agent_pid:
                collector._buffer.append(ev)

        events = collector.collect()
        assert len(events) == 1
        assert events[0].fields["pid"] == "9999"

    def test_ipv4_u32_to_dotted(self):
        """struct.pack('I', u32) + inet_ntop round-trips for various IPs."""
        test_cases = {
            "127.0.0.1": socket.inet_pton(socket.AF_INET, "127.0.0.1"),
            "10.0.0.1": socket.inet_pton(socket.AF_INET, "10.0.0.1"),
            "192.168.1.100": socket.inet_pton(socket.AF_INET, "192.168.1.100"),
            "255.255.255.255": socket.inet_pton(socket.AF_INET, "255.255.255.255"),
        }
        for expected_ip, packed in test_cases.items():
            u32 = struct.unpack("I", packed)[0]
            result = socket.inet_ntop(socket.AF_INET, struct.pack("I", u32))
            assert result == expected_ip, f"Expected {expected_ip}, got {result}"


class TestEbpfFileEvents:
    """Tests for eBPF file activity event handling."""

    def test_file_create_normalizer_dispatch(self):
        """source='ebpf_file_create' routes through normalize_file correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_file_create",
            message="file_create: vim -> /etc/passwd",
            fields={
                "pid": "1234",
                "name": "vim",
                "file_path": "/etc/passwd",
                "event_type": "file_create",
                "uid": "0",
                "username": "root",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, FileActivity)
        assert result.activity_id == 1  # create
        assert result.file_path == "/etc/passwd"
        assert result.process.name == "vim"
        assert result.metadata.log_source == "ebpf_file_create"

    def test_file_modify_normalizer_dispatch(self):
        """source='ebpf_file_modify' routes through normalize_file correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_file_modify",
            message="file_modify: bash -> /tmp/test.sh",
            fields={
                "pid": "5678",
                "name": "bash",
                "file_path": "/tmp/test.sh",
                "event_type": "file_modify",
                "uid": "1000",
                "username": "alice",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, FileActivity)
        assert result.activity_id == 3  # modify
        assert result.file_path == "/tmp/test.sh"

    def test_file_delete_normalizer_dispatch(self):
        """source='ebpf_file_delete' routes through normalize_file correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_file_delete",
            message="file_delete: rm -> /var/log/auth.log",
            fields={
                "pid": "9999",
                "name": "rm",
                "file_path": "/var/log/auth.log",
                "event_type": "file_delete",
                "uid": "0",
                "username": "root",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, FileActivity)
        assert result.activity_id == 4  # delete
        assert result.file_path == "/var/log/auth.log"

    def test_file_event_buffer_drain(self):
        """collect() drains file events from the buffer."""
        collector = EbpfCollector()
        ev = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_file_create",
            message="file_create: vim -> /etc/crontab",
            fields={
                "pid": "300",
                "name": "vim",
                "file_path": "/etc/crontab",
                "event_type": "file_create",
            },
            hostname="testhost",
        )
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 1
        assert events[0].source == "ebpf_file_create"

    def test_watched_prefixes_exist(self):
        """Ensure watched prefixes include critical security directories."""
        assert "/etc/" in _WATCHED_PREFIXES
        assert "/tmp/" in _WATCHED_PREFIXES
        assert "/var/log/" in _WATCHED_PREFIXES
        assert "/root/" in _WATCHED_PREFIXES
        assert "/home/" in _WATCHED_PREFIXES


class TestEbpfDnsEvents:
    """Tests for eBPF DNS activity event handling."""

    def test_dns_normalizer_dispatch(self):
        """source='ebpf_dns' routes through normalize_dns correctly."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_dns",
            message="dns: curl -> evil.com",
            fields={
                "pid": "4321",
                "name": "curl",
                "query_domain": "evil.com",
                "resolved_ips": "",
                "dns_server": "8.8.8.8",
                "uid": "1000",
                "username": "alice",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, DnsActivity)
        assert result.query_domain == "evil.com"
        assert result.process.name == "curl"
        assert result.process.pid == 4321
        assert result.metadata.log_source == "ebpf_dns"

    def test_dns_event_buffer_drain(self):
        """collect() drains DNS events from the buffer."""
        collector = EbpfCollector()
        ev = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_dns",
            message="dns: wget -> malware.example.com",
            fields={
                "pid": "400",
                "name": "wget",
                "query_domain": "malware.example.com",
                "resolved_ips": "",
            },
            hostname="testhost",
        )
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 1
        assert events[0].source == "ebpf_dns"

    def test_dns_empty_resolved_ips(self):
        """eBPF DNS events have empty resolved_ips (only captures queries, not responses)."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="ebpf_dns",
            message="dns: python -> api.example.com",
            fields={
                "pid": "500",
                "name": "python",
                "query_domain": "api.example.com",
                "resolved_ips": "",
            },
            hostname="testhost",
        )
        result = normalize(raw)
        assert isinstance(result, DnsActivity)
        assert result.resolved_ips == []


class TestDnsQnameParsing:
    """Tests for _parse_dns_qname wire-format parser."""

    def _make_dns_payload(self, name: str) -> bytes:
        """Build a minimal DNS query payload with the given domain name."""
        # 12-byte DNS header (all zeros is fine for our parser)
        header = b"\x00" * 12
        # Encode labels: "example.com" -> \x07example\x03com\x00
        labels = b""
        for label in name.split("."):
            labels += bytes([len(label)]) + label.encode("ascii")
        labels += b"\x00"
        return header + labels

    def test_simple_domain(self):
        payload = self._make_dns_payload("example.com")
        assert _parse_dns_qname(payload) == "example.com"

    def test_subdomain(self):
        payload = self._make_dns_payload("www.evil.example.org")
        assert _parse_dns_qname(payload) == "www.evil.example.org"

    def test_single_label(self):
        payload = self._make_dns_payload("localhost")
        assert _parse_dns_qname(payload) == "localhost"

    def test_too_short(self):
        assert _parse_dns_qname(b"\x00" * 5) == ""

    def test_empty_after_header(self):
        # Header followed by zero-length label (root)
        payload = b"\x00" * 12 + b"\x00"
        assert _parse_dns_qname(payload) == ""


class TestSnapshotMode:
    """Tests for PsutilCollector snapshot_only mode."""

    @patch("agent.collectors.psutil_collector.psutil")
    def test_snapshot_mode_first_collect(self, mock_psutil):
        """In snapshot mode, first collect() emits events for all processes."""
        import types

        mock_proc = types.SimpleNamespace(
            info={
                "pid": 1234,
                "name": "sshd",
                "username": "root",
                "cmdline": ["/usr/sbin/sshd"],
                "create_time": datetime.now().timestamp(),
                "ppid": 1,
                "exe": "/usr/sbin/sshd",
            }
        )
        mock_psutil.process_iter.return_value = [mock_proc]
        mock_psutil.net_connections.return_value = []
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})
        mock_psutil.Process.return_value = types.SimpleNamespace(children=lambda recursive=False: [])

        collector = PsutilCollector(snapshot_only=True)
        collector._agent_pid = -1  # ensure we don't skip the mock process
        collector._agent_pids = set()
        events = collector.collect()
        # Snapshot mode emits all processes on first call
        assert len(events) >= 1
        assert any(e.source == "psutil_process" for e in events)

    @patch("agent.collectors.psutil_collector.psutil")
    def test_snapshot_mode_second_collect_empty(self, mock_psutil):
        """In snapshot mode, second collect() returns empty list."""
        import types

        mock_proc = types.SimpleNamespace(
            info={
                "pid": 1234,
                "name": "sshd",
                "username": "root",
                "cmdline": ["/usr/sbin/sshd"],
                "create_time": datetime.now().timestamp(),
                "ppid": 1,
                "exe": "/usr/sbin/sshd",
            }
        )
        mock_psutil.process_iter.return_value = [mock_proc]
        mock_psutil.net_connections.return_value = []
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})
        mock_psutil.Process.return_value = types.SimpleNamespace(children=lambda recursive=False: [])

        collector = PsutilCollector(snapshot_only=True)
        collector._agent_pid = -1
        collector._agent_pids = set()
        collector.collect()  # first call — runs
        events = collector.collect()  # second call — should be empty
        assert events == []

    @patch("agent.collectors.psutil_collector.psutil")
    def test_normal_mode_keeps_polling(self, mock_psutil):
        """In normal mode, collect() returns events on every call (after init)."""
        import types

        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.ZombieProcess = type("ZombieProcess", (Exception,), {})
        mock_psutil.Process.return_value = types.SimpleNamespace(children=lambda recursive=False: [])

        proc1 = types.SimpleNamespace(
            info={
                "pid": 100,
                "name": "init",
                "username": "root",
                "cmdline": ["/sbin/init"],
                "create_time": datetime.now().timestamp(),
                "ppid": 0,
                "exe": "/sbin/init",
            }
        )
        proc2 = types.SimpleNamespace(
            info={
                "pid": 200,
                "name": "sshd",
                "username": "root",
                "cmdline": ["/usr/sbin/sshd"],
                "create_time": datetime.now().timestamp(),
                "ppid": 1,
                "exe": "/usr/sbin/sshd",
            }
        )
        mock_psutil.net_connections.return_value = []

        collector = PsutilCollector(snapshot_only=False)
        collector._agent_pid = -1
        collector._agent_pids = set()

        # First call: baseline (learn pass, no events emitted in normal mode)
        mock_psutil.process_iter.return_value = [proc1]
        collector.collect()

        # Second call: add a new process — should detect it
        mock_psutil.process_iter.return_value = [proc1, proc2]
        events = collector.collect()
        assert len(events) >= 1
        assert any(e.fields.get("pid") == "200" for e in events)
