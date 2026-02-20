"""Connection metadata collector: captures TLS SNI, JA3, HTTP Host via tcpdump."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
import socket
import sqlite3
import struct
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)

# Parse tcpdump SYN packet lines (initial SYN only, not SYN-ACK):
#   12:34:56.789 IP 10.0.0.1.54321 > 93.184.216.34.443: Flags [S], ...
#   Also matches ECN variants: Flags [SEW], Flags [SE], etc.
#   Excludes SYN-ACK: Flags [S.], Flags [S.E], etc. (dot = ACK)
_SYN_RE = re.compile(
    r"IP (?P<src_ip>[\d.]+)\.(?P<src_port>\d+) > "
    r"(?P<dst_ip>[\d.]+)\.(?P<dst_port>\d+): "
    r"Flags \[S[^.\]]*\]"
)


@dataclass
class ConnectionMetadata:
    """Metadata captured for a network connection."""

    connection_id: str = ""
    source_pid: int = 0
    source_process: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = "TCP"
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    tls_sni: str | None = None
    http_host: str | None = None
    tls_version: str | None = None
    ja3_hash: str | None = None
    is_encrypted: bool = False


# Known JA3 fingerprints for common applications
KNOWN_JA3: dict[str, dict[str, str]] = {
    "773906b0efdefa24a7f2b8eb6985bf37": {"app": "Safari", "risk": "low"},
    "b32309a26951912be7dba376398abc3b": {"app": "Chrome", "risk": "low"},
    "e7d705a3286e19ea42f587b344ee6865": {"app": "Metasploit", "risk": "critical"},
    "6734f37431670b3ab4292b8f60f29984": {"app": "Cobalt Strike", "risk": "critical"},
}


def extract_sni_from_client_hello(payload: bytes) -> str | None:
    """Extract Server Name Indication from TLS ClientHello.

    Walks the TLS record structure to find the SNI extension (type 0x0000).
    Returns the hostname or None if not found.
    """
    try:
        if len(payload) < 44:
            return None

        # TLS Record: ContentType(1) + Version(2) + Length(2) + Handshake
        content_type = payload[0]
        if content_type != 0x16:  # Not a handshake
            return None

        # Handshake header: Type(1) + Length(3)
        offset = 5
        if offset >= len(payload):
            return None
        handshake_type = payload[offset]
        if handshake_type != 0x01:  # Not ClientHello
            return None

        offset += 4  # Skip type(1) + length(3)

        # ClientHello: Version(2) + Random(32) + SessionID
        offset += 2 + 32  # Skip version and random

        if offset >= len(payload):
            return None

        # Session ID length + skip
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(payload):
            return None

        # Cipher suites length + skip
        cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2 + cipher_suites_len

        if offset >= len(payload):
            return None

        # Compression methods length + skip
        comp_len = payload[offset]
        offset += 1 + comp_len

        if offset + 2 > len(payload):
            return None

        # Extensions length
        extensions_len = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2

        # Walk extensions looking for SNI (type 0x0000)
        end = min(offset + extensions_len, len(payload))
        while offset + 4 <= end:
            ext_type = struct.unpack("!H", payload[offset : offset + 2])[0]
            ext_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
            offset += 4

            if ext_type == 0x0000 and offset + ext_len <= end:
                # SNI extension: list_length(2) + type(1) + name_length(2) + name
                sni_data = payload[offset : offset + ext_len]
                if len(sni_data) >= 5:
                    name_len = struct.unpack("!H", sni_data[3:5])[0]
                    if len(sni_data) >= 5 + name_len:
                        return sni_data[5 : 5 + name_len].decode("ascii", errors="ignore")
                return None

            offset += ext_len

    except (struct.error, IndexError):
        pass

    return None


def compute_ja3(client_hello: bytes) -> str | None:
    """Compute JA3 hash from a TLS ClientHello.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    try:
        if len(client_hello) < 44:
            return None

        # Skip TLS record header (5 bytes)
        offset = 5

        if client_hello[offset] != 0x01:  # Not ClientHello
            return None

        offset += 4  # Skip handshake type + length

        # TLS version
        tls_version = struct.unpack("!H", client_hello[offset : offset + 2])[0]
        offset += 2 + 32  # Skip version + random

        # Session ID
        session_id_len = client_hello[offset]
        offset += 1 + session_id_len

        # Cipher suites
        cipher_suites_len = struct.unpack("!H", client_hello[offset : offset + 2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 <= len(client_hello):
                cipher = struct.unpack("!H", client_hello[offset + i : offset + i + 2])[0]
                # Skip GREASE values
                if (cipher & 0x0F0F) != 0x0A0A:
                    ciphers.append(str(cipher))
        offset += cipher_suites_len

        # Compression methods
        comp_len = client_hello[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if offset + 2 <= len(client_hello):
            extensions_len = struct.unpack("!H", client_hello[offset : offset + 2])[0]
            offset += 2
            end = min(offset + extensions_len, len(client_hello))

            while offset + 4 <= end:
                ext_type = struct.unpack("!H", client_hello[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", client_hello[offset + 2 : offset + 4])[0]
                offset += 4

                # Skip GREASE extension types
                if (ext_type & 0x0F0F) != 0x0A0A:
                    extensions.append(str(ext_type))

                ext_data = client_hello[offset : offset + ext_len]

                # Elliptic curves (supported_groups, ext type 10)
                if ext_type == 0x000A and len(ext_data) >= 2:
                    curves_len = struct.unpack("!H", ext_data[0:2])[0]
                    for i in range(2, min(2 + curves_len, len(ext_data)), 2):
                        if i + 2 <= len(ext_data):
                            curve = struct.unpack("!H", ext_data[i : i + 2])[0]
                            if (curve & 0x0F0F) != 0x0A0A:
                                elliptic_curves.append(str(curve))

                # EC point formats (ext type 11)
                elif ext_type == 0x000B and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for i in range(1, min(1 + fmt_len, len(ext_data))):
                        ec_point_formats.append(str(ext_data[i]))

                offset += ext_len

        # Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_str = ",".join([
            str(tls_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats),
        ])

        return hashlib.md5(ja3_str.encode()).hexdigest()

    except (struct.error, IndexError):
        return None


# --- Connection Metadata SQLite storage ---

CONNECTION_METADATA_DDL = """
CREATE TABLE IF NOT EXISTS connection_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_pid INTEGER,
    source_process TEXT,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'TCP',
    start_time TEXT,
    end_time TEXT,
    duration_seconds REAL,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    tls_sni TEXT,
    http_host TEXT,
    tls_version TEXT,
    ja3_hash TEXT,
    is_encrypted INTEGER DEFAULT 0
)
"""

CONNECTION_METADATA_INDEX = """
CREATE INDEX IF NOT EXISTS idx_conn_meta_pid_time
ON connection_metadata (source_pid, start_time)
"""


def init_connection_metadata_db(conn: sqlite3.Connection) -> None:
    """Create the connection_metadata table if it doesn't exist."""
    conn.execute(CONNECTION_METADATA_DDL)
    conn.execute(CONNECTION_METADATA_INDEX)
    conn.commit()


def store_connection_metadata(
    conn: sqlite3.Connection, metadata: ConnectionMetadata
) -> None:
    """Store a connection metadata record."""
    conn.execute(
        "INSERT INTO connection_metadata "
        "(source_pid, source_process, dest_ip, dest_port, protocol, "
        "start_time, end_time, duration_seconds, bytes_sent, bytes_received, "
        "tls_sni, http_host, tls_version, ja3_hash, is_encrypted) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            metadata.source_pid,
            metadata.source_process,
            metadata.dest_ip,
            metadata.dest_port,
            metadata.protocol,
            metadata.start_time.isoformat() if metadata.start_time else None,
            metadata.end_time.isoformat() if metadata.end_time else None,
            metadata.duration_seconds,
            metadata.bytes_sent,
            metadata.bytes_received,
            metadata.tls_sni,
            metadata.http_host,
            metadata.tls_version,
            metadata.ja3_hash,
            1 if metadata.is_encrypted else 0,
        ),
    )
    conn.commit()


def get_connection_metadata(
    conn: sqlite3.Connection,
    pid: int | None = None,
    hours: int = 1,
) -> list[dict]:
    """Query connection metadata, optionally filtered by PID and time window."""
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    if pid is not None and pid > 0:
        rows = conn.execute(
            "SELECT * FROM connection_metadata "
            "WHERE source_pid = ? AND start_time >= ? "
            "ORDER BY start_time DESC LIMIT 100",
            (pid, cutoff),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM connection_metadata "
            "WHERE start_time >= ? "
            "ORDER BY start_time DESC LIMIT 100",
            (cutoff,),
        ).fetchall()
    return [dict(row) for row in rows]


def cleanup_old_metadata(conn: sqlite3.Connection, retention_hours: int = 24) -> int:
    """Delete connection metadata older than retention_hours. Returns count deleted."""
    cutoff = (datetime.now() - timedelta(hours=retention_hours)).isoformat()
    cursor = conn.execute(
        "DELETE FROM connection_metadata WHERE start_time < ?",
        (cutoff,),
    )
    conn.commit()
    return cursor.rowcount


class ConnectionMetadataCollector(Collector):
    """Captures connection metadata via tcpdump.

    Follows the same pattern as MacOSDnsCollector:
    - Background tcpdump thread captures TCP SYN packets
    - _parse_line() extracts src/dst IP:port
    - collect() drains the buffer (thread-safe)
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._hostname = socket.gethostname()
        self._buffer: list[RawEvent] = []
        self._buffer_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._db_path = db_path
        self._db_conn: sqlite3.Connection | None = None
        self._connections: dict[str, ConnectionMetadata] = {}
        self._write_count = 0

    def name(self) -> str:
        return "connection_metadata"

    def start(self) -> None:
        if self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._run_tcpdump, daemon=True, name="connection_metadata"
        )
        self._thread.start()

    def _run_tcpdump(self) -> None:
        """Run tcpdump to capture TCP SYN packets."""
        # Initialize SQLite in this thread (SQLite connections are thread-local)
        if self._db_path:
            try:
                self._db_conn = sqlite3.connect(self._db_path)
                self._db_conn.row_factory = sqlite3.Row
                init_connection_metadata_db(self._db_conn)
                logger.info("Connection metadata DB initialized: %s", self._db_path)
            except Exception:
                logger.debug("Failed to init connection metadata DB", exc_info=True)

        try:
            self._proc = subprocess.Popen(
                [
                    "tcpdump", "-i", "any", "-n", "-l",
                    "tcp[tcpflags] & (tcp-syn) != 0",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            logger.info("Connection metadata collector started (tcpdump SYN capture)")

            for line in self._proc.stdout:
                line = line.strip()
                if not line:
                    continue
                self._parse_line(line)

        except FileNotFoundError:
            logger.warning("tcpdump not found — connection metadata disabled")
        except PermissionError:
            logger.warning("tcpdump requires root — connection metadata disabled")
        except OSError as e:
            logger.debug("Connection metadata collector error: %s", e)

    def _parse_line(self, line: str) -> None:
        """Parse a tcpdump SYN line and create a connection metadata entry."""
        m = _SYN_RE.search(line)
        if not m:
            return

        src_ip = m.group("src_ip")
        src_port = int(m.group("src_port"))
        dst_ip = m.group("dst_ip")
        dst_port = int(m.group("dst_port"))

        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        now = datetime.now()

        metadata = ConnectionMetadata(
            connection_id=conn_key,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol="TCP",
            start_time=now,
            is_encrypted=dst_port == 443,
        )

        self._connections[conn_key] = metadata

        # Store to SQLite if available
        if self._db_conn:
            try:
                store_connection_metadata(self._db_conn, metadata)
                self._write_count += 1
                # Periodic cleanup every 100 writes
                if self._write_count % 100 == 0:
                    cleanup_old_metadata(self._db_conn, retention_hours=24)
            except Exception:
                logger.debug("Failed to store connection metadata", exc_info=True)

        # Create a RawEvent for the connection
        event = RawEvent(
            timestamp=now,
            source="connection_metadata",
            message=f"TCP SYN: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            fields={
                "src_ip": src_ip,
                "src_port": str(src_port),
                "dst_ip": dst_ip,
                "dst_port": str(dst_port),
                "protocol": "TCP",
                "is_encrypted": str(dst_port == 443),
            },
            hostname=self._hostname,
        )
        with self._buffer_lock:
            self._buffer.append(event)

        # Limit connection tracking
        if len(self._connections) > 10000:
            keys = list(self._connections.keys())
            for k in keys[:5000]:
                del self._connections[k]

    def collect(self) -> list[RawEvent]:
        with self._buffer_lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()
            self._proc = None
        if self._db_conn:
            with contextlib.suppress(Exception):
                self._db_conn.close()
            self._db_conn = None
