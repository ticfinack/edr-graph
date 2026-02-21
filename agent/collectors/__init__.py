"""Platform-aware collector dispatcher."""

from __future__ import annotations

import logging
import platform

from .base import Collector, RawEvent
from .psutil_collector import PsutilCollector

logger = logging.getLogger(__name__)

__all__ = ["collect_all", "get_collectors", "Collector", "RawEvent"]


def get_collectors(db_path: str | None = None) -> list[Collector]:
    """Return collectors appropriate for the current platform."""
    collectors: list[Collector] = []
    system = platform.system()

    if system == "Linux":
        ebpf_available = False
        try:
            from .ebpf_collector import EbpfCollector

            _probe = EbpfCollector()
            _probe.start()  # verify BPF loads
            _probe.stop()
            collectors.append(EbpfCollector())  # fresh instance
            ebpf_available = True
            logger.info("eBPF collector active, psutil in snapshot-only mode")
        except Exception:
            logger.info(
                "eBPF collector not available (requires root + BCC + kernel headers), falling back to psutil polling"
            )

        collectors.append(PsutilCollector(snapshot_only=ebpf_available))

        from .linux import LinuxCollector

        collectors.append(LinuxCollector())
        try:
            from .auditd_collector import AuditdCollector

            collectors.append(AuditdCollector())
        except Exception:
            logger.debug("Auditd collector not available", exc_info=True)
    elif system == "Darwin":
        collectors.append(PsutilCollector())
        from .macos import MacOSCollector

        collectors.append(MacOSCollector())
        try:
            from .macos_dns import MacOSDnsCollector

            collectors.append(MacOSDnsCollector())
        except Exception:
            logger.debug("macOS DNS collector not available", exc_info=True)
        fsevents_collector = None
        try:
            from .macos_fsevents_collector import MacOSFSEventsCollector

            fsevents_collector = MacOSFSEventsCollector()
            collectors.append(fsevents_collector)
        except Exception:
            logger.debug("macOS FSEvents collector not available", exc_info=True)
        try:
            from .macos_persistence_poller import MacOSPersistencePoller

            collectors.append(
                MacOSPersistencePoller(
                    fsevents_collector=fsevents_collector,
                )
            )
        except Exception:
            logger.debug("macOS persistence poller not available", exc_info=True)
        try:
            from .connection_metadata import ConnectionMetadataCollector

            collectors.append(ConnectionMetadataCollector(db_path=db_path))
        except Exception:
            logger.debug("Connection metadata collector not available", exc_info=True)
    elif system == "Windows":
        collectors.append(PsutilCollector())
        from .windows import WindowsCollector

        collectors.append(WindowsCollector())
        try:
            from .etw_collector import EtwCollector

            collectors.append(EtwCollector())
        except Exception:
            logger.debug("ETW collector not available", exc_info=True)
    else:
        collectors.append(PsutilCollector())
        logger.warning("Unknown platform %s, using psutil only", system)

    return collectors


def collect_all(collectors: list[Collector]) -> list[RawEvent]:
    """Run all collectors and aggregate their events."""
    events: list[RawEvent] = []
    for collector in collectors:
        try:
            events.extend(collector.collect())
        except Exception:
            logger.exception("Collector %s failed", collector.name())
    return events
