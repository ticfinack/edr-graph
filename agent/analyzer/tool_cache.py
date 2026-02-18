"""Per-batch TTL cache for tool-use results."""

from __future__ import annotations

import json
import time


class ToolCache:
    """Simple in-memory cache keyed by 'tool_name:json_args'.

    Created fresh per ``analyze_batch()`` call so the same IP / domain is
    only looked up once within a single analysis run.  A 300-second TTL
    acts as a safety net for long-running batches.
    """

    def __init__(self, ttl: float = 300.0) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[str, float]] = {}

    @staticmethod
    def _make_key(tool_name: str, arguments: dict) -> str:
        return f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"

    def get(self, tool_name: str, arguments: dict) -> str | None:
        key = self._make_key(tool_name, arguments)
        entry = self._store.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        return value

    def put(self, tool_name: str, arguments: dict, result: str) -> None:
        key = self._make_key(tool_name, arguments)
        self._store[key] = (result, time.monotonic())

    @property
    def size(self) -> int:
        return len(self._store)
