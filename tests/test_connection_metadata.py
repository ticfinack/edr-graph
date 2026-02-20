"""Tests for connection metadata collector."""

from __future__ import annotations

import hashlib
import sqlite3
import struct
from datetime import datetime, timedelta

import pytest

from agent.collectors.connection_metadata import (
    _SYN_RE,
    KNOWN_JA3,
    ConnectionMetadata,
    ConnectionMetadataCollector,
    cleanup_old_metadata,
    compute_ja3,
    extract_sni_from_client_hello,
    get_connection_metadata,
    init_connection_metadata_db,
    store_connection_metadata,
)


def _build_tls_client_hello(sni: str = "example.com") -> bytes:
    """Build a minimal TLS ClientHello with SNI extension for testing."""
    # SNI extension data
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes  # type(1) + length(2) + name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry  # list_length(2) + entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list  # type(2) + length(2) + data

    # Cipher suites (2 ciphers)
    ciphers = struct.pack("!HHH", 4, 0x1301, 0x1302)  # length(2) + 2 ciphers

    # Compression methods
    comp = struct.pack("!BB", 1, 0)  # length(1) + null(1)

    # Extensions
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    # ClientHello body: version(2) + random(32) + session_id_len(1) + ciphers + comp + extensions
    ch_body = (
        struct.pack("!H", 0x0303)  # TLS 1.2
        + b"\x00" * 32  # Random
        + struct.pack("!B", 0)  # Session ID length = 0
        + ciphers
        + comp
        + extensions
    )

    # Handshake header: type(1) + length(3)
    hs_header = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body))[1:]  # 3-byte length

    # TLS record header: content_type(1) + version(2) + length(2)
    record = struct.pack("!BHH", 0x16, 0x0301, len(hs_header) + len(ch_body))

    return record + hs_header + ch_body


class TestSNIExtraction:
    def test_extract_sni_basic(self):
        """Extract SNI from a well-formed ClientHello."""
        payload = _build_tls_client_hello("example.com")
        sni = extract_sni_from_client_hello(payload)
        assert sni == "example.com"

    def test_extract_sni_different_domain(self):
        payload = _build_tls_client_hello("api.github.com")
        sni = extract_sni_from_client_hello(payload)
        assert sni == "api.github.com"

    def test_extract_sni_not_tls(self):
        """Non-TLS data should return None."""
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        sni = extract_sni_from_client_hello(payload)
        assert sni is None

    def test_extract_sni_too_short(self):
        payload = b"\x16\x03\x01"
        sni = extract_sni_from_client_hello(payload)
        assert sni is None

    def test_extract_sni_empty(self):
        sni = extract_sni_from_client_hello(b"")
        assert sni is None


class TestJA3:
    def test_compute_ja3_returns_hash(self):
        """JA3 should return a 32-char hex MD5 hash."""
        payload = _build_tls_client_hello("example.com")
        ja3 = compute_ja3(payload)
        assert ja3 is not None
        assert len(ja3) == 32
        # All hex chars
        assert all(c in "0123456789abcdef" for c in ja3)

    def test_compute_ja3_not_tls(self):
        ja3 = compute_ja3(b"not tls data at all")
        assert ja3 is None

    def test_compute_ja3_deterministic(self):
        """Same input should produce same JA3."""
        payload = _build_tls_client_hello("test.example.com")
        ja3_1 = compute_ja3(payload)
        ja3_2 = compute_ja3(payload)
        assert ja3_1 == ja3_2

    def test_known_ja3_lookup(self):
        """Known JA3 entries should have expected fields."""
        for ja3_hash, info in KNOWN_JA3.items():
            assert "app" in info
            assert "risk" in info
            assert len(ja3_hash) == 32


class TestSYNParsing:
    def test_parse_syn_line(self):
        """Regex should match a SYN packet line."""
        line = "12:34:56.789012 IP 10.0.0.1.54321 > 93.184.216.34.443: Flags [S], seq 12345"
        m = _SYN_RE.search(line)
        assert m is not None
        assert m.group("src_ip") == "10.0.0.1"
        assert m.group("src_port") == "54321"
        assert m.group("dst_ip") == "93.184.216.34"
        assert m.group("dst_port") == "443"

    def test_parse_syn_with_ecn(self):
        """SYN with ECN flags (SEW) should match."""
        line = "07:34:28.465722 IP 10.199.0.7.50666 > 104.18.26.120.443: Flags [SEW], seq 375125515"
        m = _SYN_RE.search(line)
        assert m is not None
        assert m.group("src_ip") == "10.199.0.7"
        assert m.group("dst_port") == "443"

    def test_parse_syn_ack_excluded(self):
        """SYN-ACK (Flags [S.]) should NOT match — we only want initial SYNs."""
        line = "07:34:28.524714 IP 104.18.26.120.443 > 10.199.0.7.50666: Flags [S.E], seq 675966147"
        m = _SYN_RE.search(line)
        assert m is None

    def test_parse_non_syn(self):
        """Non-SYN lines should not match."""
        line = "12:34:56.789012 IP 10.0.0.1.54321 > 93.184.216.34.443: Flags [.], ack 1"
        m = _SYN_RE.search(line)
        assert m is None


class TestConnectionMetadataStorage:
    @pytest.fixture
    def db(self, tmp_path):
        conn = sqlite3.connect(str(tmp_path / "test.db"))
        conn.row_factory = sqlite3.Row
        init_connection_metadata_db(conn)
        yield conn
        conn.close()

    def test_store_and_retrieve(self, db):
        now = datetime.now()
        meta = ConnectionMetadata(
            connection_id="test",
            source_pid=100,
            source_process="curl",
            dest_ip="93.184.216.34",
            dest_port=443,
            start_time=now,
            tls_sni="example.com",
            is_encrypted=True,
        )
        store_connection_metadata(db, meta)

        rows = get_connection_metadata(db, pid=100, hours=1)
        assert len(rows) == 1
        assert rows[0]["dest_ip"] == "93.184.216.34"
        assert rows[0]["tls_sni"] == "example.com"
        assert rows[0]["is_encrypted"] == 1

    def test_cleanup_old_entries(self, db):
        """Entries older than retention period should be cleaned up."""
        old_time = datetime.now() - timedelta(hours=48)
        meta = ConnectionMetadata(
            connection_id="old",
            dest_ip="1.2.3.4",
            dest_port=80,
            start_time=old_time,
        )
        store_connection_metadata(db, meta)

        # Should have 1 entry
        rows = get_connection_metadata(db, hours=100)
        assert len(rows) == 1

        # Cleanup with 24h retention
        deleted = cleanup_old_metadata(db, retention_hours=24)
        assert deleted == 1

        # Should have 0 entries
        rows = get_connection_metadata(db, hours=100)
        assert len(rows) == 0

    def test_query_by_pid(self, db):
        now = datetime.now()
        for pid in [100, 200, 100]:
            meta = ConnectionMetadata(
                dest_ip="1.2.3.4",
                dest_port=80,
                source_pid=pid,
                start_time=now,
            )
            store_connection_metadata(db, meta)

        rows_100 = get_connection_metadata(db, pid=100, hours=1)
        assert len(rows_100) == 2

        rows_200 = get_connection_metadata(db, pid=200, hours=1)
        assert len(rows_200) == 1


class TestCollectorParsing:
    def test_collector_parse_line(self):
        """Collector._parse_line should buffer events from SYN lines."""
        collector = ConnectionMetadataCollector()
        collector._parse_line(
            "12:34:56.789 IP 10.0.0.1.54321 > 93.184.216.34.443: Flags [S], seq 1"
        )

        events = collector.collect()
        assert len(events) == 1
        assert events[0].fields["dst_ip"] == "93.184.216.34"
        assert events[0].fields["dst_port"] == "443"

    def test_collector_ignores_non_syn(self):
        collector = ConnectionMetadataCollector()
        collector._parse_line("some random log line")
        events = collector.collect()
        assert len(events) == 0

    def test_collect_drains_buffer(self):
        """collect() should drain buffer atomically."""
        collector = ConnectionMetadataCollector()
        collector._parse_line(
            "12:34:56.789 IP 10.0.0.1.54321 > 1.2.3.4.80: Flags [S], seq 1"
        )
        events1 = collector.collect()
        events2 = collector.collect()
        assert len(events1) == 1
        assert len(events2) == 0
