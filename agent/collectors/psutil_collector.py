"""Cross-platform collector using psutil for process and network events."""

from __future__ import annotations

import contextlib
import logging
import os
import socket
from datetime import datetime

import psutil

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)


class PsutilCollector(Collector):
    """Collects process and network connection events via psutil.

    Diffs against previous snapshots to detect new processes and connections.
    """

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._prev_pids: set[int] = set()
        self._prev_conns: set[tuple] = set()
        self._initialized = False
        self._agent_pid = os.getpid()
        self._agent_pids: set[int] = set()  # refreshed each cycle

    def name(self) -> str:
        return "psutil"

    def collect(self) -> list[RawEvent]:
        self._refresh_agent_pids()
        events: list[RawEvent] = []
        events.extend(self._collect_processes())
        events.extend(self._collect_network())
        return events

    def _refresh_agent_pids(self) -> None:
        """Build set of PIDs belonging to the agent's own process tree."""
        pids = {self._agent_pid}
        try:
            parent = psutil.Process(self._agent_pid)
            for child in parent.children(recursive=True):
                pids.add(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        self._agent_pids = pids

    def _collect_processes(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        current_pids: set[int] = set()
        now = datetime.now()

        for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time", "ppid", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if self._initialized and pid not in self._prev_pids and pid not in self._agent_pids:
                    cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""
                    create_time = datetime.fromtimestamp(info["create_time"]) if info["create_time"] else now
                    events.append(
                        RawEvent(
                            timestamp=create_time,
                            source="psutil_process",
                            message=f"New process: {info['name']} (PID {pid})",
                            fields={
                                "pid": str(pid),
                                "name": info["name"] or "",
                                "username": info["username"] or "",
                                "cmdline": cmdline,
                                "exe": info["exe"] or "",
                                "ppid": str(info["ppid"] or 0),
                                "create_time": create_time.isoformat(),
                            },
                            hostname=self._hostname,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._prev_pids = current_pids
        if not self._initialized:
            self._initialized = True
        return events

    def _collect_network(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        current_conns: set[tuple] = set()
        now = datetime.now()

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            logger.debug("Cannot access network connections (needs elevated privileges)")
            return events

        for conn in connections:
            if conn.status != "ESTABLISHED" and conn.status != "LISTEN":
                continue
            if not conn.raddr:
                continue

            conn_key = (
                conn.pid or 0,
                conn.laddr.ip if conn.laddr else "",
                conn.laddr.port if conn.laddr else 0,
                conn.raddr.ip,
                conn.raddr.port,
            )
            current_conns.add(conn_key)

            if self._initialized and conn_key not in self._prev_conns and (conn.pid or 0) not in self._agent_pids:
                proc_name = ""
                if conn.pid:
                    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = psutil.Process(conn.pid).name()

                events.append(
                    RawEvent(
                        timestamp=now,
                        source="psutil_network",
                        message=(f"New connection: {proc_name or 'unknown'} -> {conn.raddr.ip}:{conn.raddr.port}"),
                        fields={
                            "pid": str(conn.pid or 0),
                            "process_name": proc_name,
                            "src_ip": conn.laddr.ip if conn.laddr else "",
                            "src_port": str(conn.laddr.port if conn.laddr else 0),
                            "dst_ip": conn.raddr.ip,
                            "dst_port": str(conn.raddr.port),
                            "status": conn.status,
                            "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        },
                        hostname=self._hostname,
                    )
                )

        self._prev_conns = current_conns
        return events
