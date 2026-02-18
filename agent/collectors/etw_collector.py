"""Windows ETW (Event Tracing for Windows) real-time collector.

Subscribes to kernel ETW providers for process, network, DNS, file, and
registry events. A consumer thread reads events into a bounded deque;
collect() drains the deque on each poll cycle.

Requires the ``pywintrace`` package (Windows only).
"""

from __future__ import annotations

import collections
import logging
import socket
import threading
from datetime import datetime

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)

# ETW provider GUIDs
_PROVIDERS = {
    "Microsoft-Windows-Kernel-Process": "process",
    "Microsoft-Windows-Kernel-Network": "network",
    "Microsoft-Windows-DNS-Client": "dns",
    "Microsoft-Windows-Kernel-File": "file",
    "Microsoft-Windows-Kernel-Registry": "registry",
}

# Map provider short name to RawEvent source
_SOURCE_MAP = {
    "process": "etw_process",
    "network": "etw_network",
    "dns": "etw_dns",
    "file": "etw_file",
    "registry": "etw_registry",
}

_BUFFER_MAX = 10_000


class EtwCollector(Collector):
    """Real-time ETW event collector for Windows.

    Architecture:
    - ``start()`` spawns a consumer thread that subscribes to ETW providers
    - Events are buffered in a bounded ``collections.deque`` with a lock
    - ``collect()`` drains the deque (called by collector thread every ~5s)
    - ``stop()`` tears down the ETW trace session
    """

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._buffer: collections.deque[RawEvent] = collections.deque(maxlen=_BUFFER_MAX)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._session = None  # pywintrace session

    def name(self) -> str:
        return "etw"

    def start(self) -> None:
        """Spawn the ETW consumer thread."""
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._consume, daemon=True, name="etw-consumer"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the consumer thread to stop and tear down the ETW session."""
        self._stop_event.set()
        if self._session is not None:
            try:
                self._session.stop()
            except Exception:
                logger.debug("Error stopping ETW session", exc_info=True)
            self._session = None
        self._thread = None

    def collect(self) -> list[RawEvent]:
        """Drain buffered events."""
        events: list[RawEvent] = []
        with self._lock:
            while self._buffer:
                events.append(self._buffer.popleft())
        return events

    def _consume(self) -> None:
        """Subscribe to ETW providers and push events into the buffer."""
        try:
            import pywintrace  # noqa: F811

            self._session = pywintrace.TraceSession("edr-agent-etw")
            for provider_name, category in _PROVIDERS.items():
                self._session.enable_provider(provider_name)

            def _on_event(event_data):
                if self._stop_event.is_set():
                    return
                source = _classify_event(event_data)
                raw = RawEvent(
                    timestamp=datetime.now(),
                    source=source,
                    message=str(event_data.get("EventName", "")),
                    fields=_extract_fields(event_data),
                    hostname=self._hostname,
                )
                with self._lock:
                    self._buffer.append(raw)

            self._session.set_callback(_on_event)
            self._session.start()  # blocks until session.stop()
        except ImportError:
            logger.warning("pywintrace not available — ETW collector disabled")
        except Exception:
            logger.debug("ETW consumer error", exc_info=True)


def _classify_event(event_data: dict) -> str:
    """Map an ETW event to our source taxonomy."""
    provider = event_data.get("ProviderName", "")
    for prov_name, category in _PROVIDERS.items():
        if prov_name in provider:
            return _SOURCE_MAP[category]
    return "etw_process"  # fallback


def _extract_fields(event_data: dict) -> dict[str, str]:
    """Extract relevant fields from an ETW event."""
    fields: dict[str, str] = {}
    for key in ("ProcessId", "ImageFileName", "CommandLine",
                "SourceAddress", "DestAddress", "SourcePort", "DestPort",
                "QueryName", "QueryResults",
                "FileName", "KeyName", "ValueName"):
        val = event_data.get(key)
        if val is not None:
            fields[key.lower()] = str(val)
    # Map to common field names
    if "processid" in fields:
        fields["pid"] = fields["processid"]
    if "imagefilename" in fields:
        fields["name"] = fields["imagefilename"]
    if "commandline" in fields:
        fields["cmdline"] = fields["commandline"]
    if "destaddress" in fields:
        fields["dst_ip"] = fields["destaddress"]
    if "destport" in fields:
        fields["dst_port"] = fields["destport"]
    if "sourceaddress" in fields:
        fields["src_ip"] = fields["sourceaddress"]
    if "sourceport" in fields:
        fields["src_port"] = fields["sourceport"]
    return fields
