"""Base types for event collectors."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class RawEvent:
    timestamp: datetime
    source: str  # "journald", "auditd", "psutil_process", "psutil_network", etc.
    message: str
    fields: dict[str, str] = field(default_factory=dict)
    hostname: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return json.dumps(d)

    @classmethod
    def from_dict(cls, data: dict) -> RawEvent:
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source=data["source"],
            message=data["message"],
            fields=data.get("fields", {}),
            hostname=data.get("hostname", ""),
        )


class Collector(ABC):
    """Abstract base class for event collectors."""

    @abstractmethod
    def collect(self) -> list[RawEvent]:
        """Collect raw events. Called periodically by the collector thread."""
        ...

    @abstractmethod
    def name(self) -> str:
        """Return the collector name."""
        ...

    def start(self) -> None:
        """Start background collection (override for push-based collectors)."""
        pass

    def stop(self) -> None:
        """Stop background collection and release resources."""
        pass
