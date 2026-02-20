"""Listening port mapper: map destination ports to listening processes."""

from __future__ import annotations

import contextlib
import logging
import time
from dataclasses import dataclass

import psutil

from agent.enrichment.process_identity import ProcessIdentity, get_process_identity

logger = logging.getLogger(__name__)


@dataclass
class ListeningService:
    """A process listening on a port."""

    port: int
    protocol: str  # "tcp" or "udp"
    pid: int
    process_name: str
    bind_address: str  # e.g. "0.0.0.0", "127.0.0.1", "::"
    identity: ProcessIdentity | None = None


@dataclass
class ConnectionContext:
    """Context for a network connection, combining source + destination info."""

    source_process: str
    source_pid: int
    source_identity: ProcessIdentity | None

    dest_ip: str
    dest_port: int
    dest_process: str | None = None
    dest_pid: int | None = None
    dest_identity: ProcessIdentity | None = None

    is_localhost_ipc: bool = False
    is_known_app_to_known_app: bool = False
    connection_description: str = ""


_LOCALHOST_ADDRS = {"127.0.0.1", "::1", "localhost"}
_WILDCARD_ADDRS = {"0.0.0.0", "::", "*"}


class PortMapper:
    """Maps listening ports to processes for connection context."""

    def __init__(self, refresh_interval: float = 30.0) -> None:
        self._refresh_interval = refresh_interval
        self._port_map: dict[tuple[str, int], ListeningService] = {}
        self._last_refresh: float = 0.0

    def refresh(self) -> None:
        """Rebuild the port map from psutil.net_connections()."""
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return

        new_map: dict[tuple[str, int], ListeningService] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "LISTEN":
                    continue
                if conn.pid is None:
                    continue

                laddr = conn.laddr
                if not laddr:
                    continue

                bind_addr = laddr.ip
                port = laddr.port

                # Get process name
                try:
                    proc = psutil.Process(conn.pid)
                    name = proc.name()
                    exe = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = ""
                    exe = ""

                # Get identity for the listener
                identity = None
                if exe:
                    with contextlib.suppress(Exception):
                        identity = get_process_identity(conn.pid, exe)

                service = ListeningService(
                    port=port,
                    protocol="tcp",
                    pid=conn.pid,
                    process_name=name,
                    bind_address=bind_addr,
                    identity=identity,
                )
                new_map[(bind_addr, port)] = service

        except (psutil.AccessDenied, OSError):
            logger.debug("Failed to refresh port map", exc_info=True)

        self._port_map = new_map
        self._last_refresh = now
        logger.debug("Port map refreshed: %d listeners", len(new_map))

    def get_listener(self, ip: str, port: int) -> ListeningService | None:
        """Look up which process is listening on ip:port.

        Falls back to wildcard addresses (0.0.0.0, ::) if exact match not found.
        """
        self.refresh()

        # Exact match
        svc = self._port_map.get((ip, port))
        if svc:
            return svc

        # Wildcard fallback for localhost connections
        for wildcard in ("0.0.0.0", "::", "*"):
            svc = self._port_map.get((wildcard, port))
            if svc:
                return svc

        return None

    def build_connection_context(
        self,
        src_pid: int,
        src_name: str,
        src_identity: ProcessIdentity | None,
        dst_ip: str,
        dst_port: int,
    ) -> ConnectionContext:
        """Build a ConnectionContext for a connection."""
        listener = self.get_listener(dst_ip, dst_port)

        ctx = ConnectionContext(
            source_process=src_name,
            source_pid=src_pid,
            source_identity=src_identity,
            dest_ip=dst_ip,
            dest_port=dst_port,
        )

        if listener:
            ctx.dest_process = listener.process_name
            ctx.dest_pid = listener.pid
            ctx.dest_identity = listener.identity

        # Determine if localhost IPC
        if dst_ip in _LOCALHOST_ADDRS or dst_ip.startswith("127."):
            ctx.is_localhost_ipc = True

        # Check if both sides are signed
        src_signed = src_identity.code_signed if src_identity else False
        dst_signed = listener.identity.code_signed if listener and listener.identity else False
        ctx.is_known_app_to_known_app = src_signed and dst_signed

        # Build description
        parts = []
        if ctx.is_localhost_ipc:
            parts.append("Localhost IPC")
        else:
            parts.append("External connection")

        parts.append(f"{src_name}(PID {src_pid})")
        if listener:
            parts.append(f"-> {listener.process_name}(PID {listener.pid})")
        else:
            parts.append(f"-> {dst_ip}:{dst_port}")

        if ctx.is_known_app_to_known_app:
            parts.append("[both signed]")

        ctx.connection_description = " ".join(parts)
        return ctx
