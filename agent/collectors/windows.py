"""Windows-specific collector: Event Log, Sysmon."""

from __future__ import annotations

import logging
import socket
from datetime import datetime

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)


class WindowsCollector(Collector):
    """Collects events from Windows Event Log and Sysmon."""

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._last_record_numbers: dict[str, int] = {}
        self._channels = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
        ]

    def name(self) -> str:
        return "windows"

    def collect(self) -> list[RawEvent]:
        events: list[RawEvent] = []
        try:
            import win32evtlog
        except ImportError:
            logger.debug("win32evtlog not available (not on Windows)")
            return events

        for channel in self._channels:
            events.extend(self._read_channel(channel, win32evtlog))

        return events

    def _read_channel(self, channel: str, win32evtlog) -> list[RawEvent]:
        """Read new events from a Windows Event Log channel."""
        events: list[RawEvent] = []
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)

            last_record = self._last_record_numbers.get(channel, total)
            if last_record >= total:
                win32evtlog.CloseEventLog(hand)
                return events

            records = win32evtlog.ReadEventLog(hand, flags, 0)
            for record in records:
                record_num = record.RecordNumber
                if record_num <= last_record:
                    continue

                source_name = record.SourceName or ""
                event_id = record.EventID & 0xFFFF
                strings = record.StringInserts or ()
                message = " | ".join(strings) if strings else ""

                fields = {
                    "event_id": str(event_id),
                    "source_name": source_name,
                    "channel": channel,
                    "event_category": str(record.EventCategory),
                    "event_type": str(record.EventType),
                }

                # Sysmon-specific field extraction
                if "Sysmon" in channel and strings:
                    fields.update(self._parse_sysmon(event_id, strings))

                events.append(
                    RawEvent(
                        timestamp=(
                            datetime.fromtimestamp(record.TimeGenerated.timestamp())
                            if record.TimeGenerated
                            else datetime.now()
                        ),
                        source=f"evtlog_{channel}",
                        message=message[:500],
                        fields=fields,
                        hostname=self._hostname,
                    )
                )

                self._last_record_numbers[channel] = max(self._last_record_numbers.get(channel, 0), record_num)

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logger.debug("Cannot read channel %s: %s", channel, e)

        return events

    @staticmethod
    def _parse_sysmon(event_id: int, strings: tuple) -> dict[str, str]:
        """Extract Sysmon-specific fields based on event ID."""
        fields: dict[str, str] = {}
        # Event ID 1: Process Create
        if event_id == 1 and len(strings) >= 5:
            fields["sysmon_type"] = "ProcessCreate"
            fields["image"] = strings[4] if len(strings) > 4 else ""
            fields["commandline"] = strings[10] if len(strings) > 10 else ""
            fields["user"] = strings[12] if len(strings) > 12 else ""
        # Event ID 3: Network Connection
        elif event_id == 3 and len(strings) >= 5:
            fields["sysmon_type"] = "NetworkConnect"
            fields["dst_ip"] = strings[14] if len(strings) > 14 else ""
            fields["dst_port"] = strings[16] if len(strings) > 16 else ""
        return fields
