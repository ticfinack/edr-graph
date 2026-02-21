"""Tests for file attribution heuristic and normalizer integration."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from agent.collectors.base import RawEvent
from agent.enrichment.file_attribution import FileAttributionCache, FileOwner
from agent.normalizer.file_activity import normalize_file


class TestFileAttributionLookup:
    """Test the 2-tier lookup heuristic."""

    def _make_cache(self, file_map: dict, dir_map: dict, agent_pid: int = 0) -> FileAttributionCache:
        cache = FileAttributionCache(refresh_interval=9999)
        cache._file_to_procs = file_map
        cache._dir_to_procs = dir_map
        cache._last_refresh = 1e18  # prevent auto-refresh
        if agent_pid:
            cache.set_agent_pid(agent_pid)
        return cache

    def test_tier1_exact_file_match(self):
        """Process has the exact file open -> returned."""
        owner = FileOwner(pid=100, name="vim", parent_pid=1)
        cache = self._make_cache(
            file_map={"/home/user/project/main.py": [owner]},
            dir_map={},
        )
        result = cache.lookup("/home/user/project/main.py")
        assert result is not None
        assert result.pid == 100
        assert result.name == "vim"

    def test_tier2_parent_dir_match(self):
        """Process has a different file open in the same directory -> returned."""
        owner = FileOwner(pid=200, name="git", parent_pid=1)
        cache = self._make_cache(
            file_map={},
            dir_map={"/repo/.git": [owner]},
        )
        result = cache.lookup("/repo/.git/index.lock")
        assert result is not None
        assert result.pid == 200
        assert result.name == "git"

    def test_no_match_beyond_tier2(self):
        """Process has file open 2+ dirs up -> None returned (the ALDente case)."""
        # ALDente has a file open under /Users/thomas but the event is for
        # /Users/thomas/Development/edr-graph/.git/index.lock
        # The parent dir of the event is /Users/thomas/Development/edr-graph/.git
        # ALDente only appears at /Users/thomas -- 3 levels up, should NOT match.
        aldente = FileOwner(pid=300, name="ALDente", parent_pid=1)
        cache = self._make_cache(
            file_map={},
            dir_map={"/Users/thomas": [aldente]},
        )
        result = cache.lookup("/Users/thomas/Development/edr-graph/.git/index.lock")
        assert result is None

    def test_tier1_preferred_over_tier2(self):
        """Exact file match wins even when parent dir has a different process."""
        vim = FileOwner(pid=100, name="vim", parent_pid=1)
        git = FileOwner(pid=200, name="git", parent_pid=1)
        cache = self._make_cache(
            file_map={"/repo/file.txt": [vim]},
            dir_map={"/repo": [git]},
        )
        result = cache.lookup("/repo/file.txt")
        assert result is not None
        assert result.pid == 100
        assert result.name == "vim"

    def test_agent_pid_excluded(self):
        """Agent's own process is skipped even if it matches."""
        agent = FileOwner(pid=999, name="edr-agent", parent_pid=1)
        real = FileOwner(pid=500, name="code", parent_pid=1)
        cache = self._make_cache(
            file_map={"/repo/file.txt": [agent, real]},
            dir_map={},
            agent_pid=999,
        )
        result = cache.lookup("/repo/file.txt")
        assert result is not None
        assert result.pid == 500
        assert result.name == "code"

    def test_agent_pid_excluded_returns_none_if_only_match(self):
        """If only the agent matches, return None."""
        agent = FileOwner(pid=999, name="edr-agent", parent_pid=1)
        cache = self._make_cache(
            file_map={"/repo/file.txt": [agent]},
            dir_map={"/repo": [agent]},
            agent_pid=999,
        )
        result = cache.lookup("/repo/file.txt")
        assert result is None

    def test_no_match_returns_none(self):
        """Completely unknown file -> None."""
        cache = self._make_cache(file_map={}, dir_map={})
        result = cache.lookup("/some/random/path.txt")
        assert result is None

    def test_pid_zero_skipped(self):
        """Processes with pid=0 are skipped."""
        bad = FileOwner(pid=0, name="kernel", parent_pid=0)
        cache = self._make_cache(
            file_map={"/tmp/test": [bad]},
            dir_map={},
        )
        result = cache.lookup("/tmp/test")
        assert result is None


class TestNormalizerIntegration:
    """Test that the normalizer handles attribution results correctly."""

    def _make_raw_event(self, file_path: str, process_name: str = "unknown") -> RawEvent:
        return RawEvent(
            timestamp=datetime(2025, 6, 1, 12, 0),
            source="fsevents",
            message=f"File modified: {file_path}",
            fields={
                "pid": "0",
                "process_name": process_name,
                "file_path": file_path,
                "event_type": "file_modify",
            },
            hostname="testhost",
        )

    @patch("agent.enrichment.file_attribution.get_file_attribution_cache")
    def test_attribution_none_clears_unknown_process(self, mock_get_cache):
        """When lookup returns None and raw name is 'unknown', process should be None."""
        mock_cache = mock_get_cache.return_value
        mock_cache.lookup.return_value = None

        raw = self._make_raw_event("/repo/.git/index.lock", process_name="unknown")
        result = normalize_file(raw)

        assert result.process is None

    @patch("agent.enrichment.file_attribution.get_file_attribution_cache")
    def test_attribution_none_clears_empty_process(self, mock_get_cache):
        """When lookup returns None and raw name is empty, process should be None."""
        mock_cache = mock_get_cache.return_value
        mock_cache.lookup.return_value = None

        raw = self._make_raw_event("/repo/.git/index.lock", process_name="")
        result = normalize_file(raw)

        assert result.process is None

    @patch("agent.enrichment.file_attribution.get_file_attribution_cache")
    def test_attribution_success_sets_process(self, mock_get_cache):
        """When lookup returns a real FileOwner, process has correct pid/name."""
        owner = FileOwner(pid=1234, name="git", parent_pid=1)
        mock_cache = mock_get_cache.return_value
        mock_cache.lookup.return_value = owner

        raw = self._make_raw_event("/repo/.git/index.lock")
        result = normalize_file(raw)

        assert result.process is not None
        assert result.process.pid == 1234
        assert result.process.name == "git"
