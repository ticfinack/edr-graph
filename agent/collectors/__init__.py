"""Platform-aware collector dispatcher."""

from __future__ import annotations

import platform
import logging

from .base import Collector, RawEvent
from .psutil_collector import PsutilCollector

logger = logging.getLogger(__name__)

__all__ = ["collect_all", "get_collectors", "Collector", "RawEvent"]


def get_collectors() -> list[Collector]:
    """Return collectors appropriate for the current platform."""
    collectors: list[Collector] = [PsutilCollector()]
    system = platform.system()

    if system == "Linux":
        from .linux import LinuxCollector
        collectors.append(LinuxCollector())
        try:
            from .auditd_collector import AuditdCollector
            collectors.append(AuditdCollector())
        except Exception:
            logger.debug("Auditd collector not available", exc_info=True)
    elif system == "Darwin":
        from .macos import MacOSCollector
        collectors.append(MacOSCollector())
    elif system == "Windows":
        from .windows import WindowsCollector
        collectors.append(WindowsCollector())
        try:
            from .etw_collector import EtwCollector
            collectors.append(EtwCollector())
        except Exception:
            logger.debug("ETW collector not available", exc_info=True)
    else:
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
