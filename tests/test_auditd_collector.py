"""Tests for the Linux auditd netlink collector."""

import struct
from datetime import datetime

from agent.collectors.auditd_collector import (
    AuditdCollector,
    _parse_audit_kv,
    _NLMSG_HDR,
    AUDIT_EXECVE,
    AUDIT_SYSCALL,
)
from agent.collectors.base import RawEvent
from agent.normalizer import normalize


class TestAuditdCollector:
    def test_buffer_drain(self):
        """collect() drains the internal buffer."""
        collector = AuditdCollector()
        ev = RawEvent(
            timestamp=datetime.now(),
            source="auditd_execve",
            message="test",
            fields={"pid": "100", "name": "bash"},
            hostname="testhost",
        )
        collector._buffer.append(ev)
        collector._buffer.append(ev)
        events = collector.collect()
        assert len(events) == 2
        assert len(collector._buffer) == 0

    def test_netlink_message_parsing(self):
        """_parse_netlink_messages correctly parses a netlink header + payload."""
        collector = AuditdCollector()
        payload = b'type=EXECVE msg=audit(123): argc=1 a0="ls"\x00'
        # Build a valid netlink message
        msg_len = _NLMSG_HDR.size + len(payload)
        header = _NLMSG_HDR.pack(msg_len, AUDIT_EXECVE, 0, 0, 0)
        data = header + payload
        collector._parse_netlink_messages(data)
        assert len(collector._buffer) == 1
        event = collector._buffer[0]
        assert event.source == "auditd_execve"

    def test_audit_kv_parsing(self):
        """_parse_audit_kv extracts key=value pairs from audit messages."""
        text = 'type=SYSCALL msg=audit(123): arch=c000003e syscall=59 pid=1234 exe="/bin/bash" comm="bash"'
        fields = _parse_audit_kv(text)
        assert fields["type"] == "SYSCALL"
        assert fields["pid"] == "1234"
        assert fields["exe"] == "/bin/bash"
        assert fields["name"] == "bash"  # derived from exe
        assert fields["comm"] == "bash"

    def test_normalizer_mapping(self):
        """auditd_execve and auditd_syscall are mapped in the normalizer."""
        raw = RawEvent(
            timestamp=datetime.now(),
            source="auditd_execve",
            message='type=EXECVE argc=1 a0="ls"',
            fields={"pid": "1234", "name": "ls", "exe": "/bin/ls"},
            hostname="testhost",
        )
        result = normalize(raw)
        assert result is not None
        assert result.process.name == "ls"
