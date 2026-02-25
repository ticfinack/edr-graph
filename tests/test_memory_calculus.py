"""Tests for dynamic memory calculus in agent.config."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _make_cgroup_fs(tmp_path, proc_self_cgroup=None, service_memory_max=None,
                    root_memory_max=None, v1_limit=None):
    """Create a fake cgroup filesystem under tmp_path for testing.

    Returns a patched _read_cgroup_memory_limit that uses the fake FS.
    """
    if proc_self_cgroup is not None:
        proc_self = tmp_path / "proc_self_cgroup"
        proc_self.write_text(proc_self_cgroup)

    if service_memory_max is not None:
        # e.g. /sys/fs/cgroup/system.slice/edr-agent.service/memory.max
        parts = proc_self_cgroup.strip().split("::", 1)
        if len(parts) == 2:
            cgroup_rel = parts[1].lstrip("/")
            mem_dir = tmp_path / "sys_fs_cgroup" / cgroup_rel
            mem_dir.mkdir(parents=True, exist_ok=True)
            (mem_dir / "memory.max").write_text(str(service_memory_max) + "\n")

    if root_memory_max is not None:
        root_dir = tmp_path / "sys_fs_cgroup"
        root_dir.mkdir(parents=True, exist_ok=True)
        (root_dir / "memory.max").write_text(str(root_memory_max) + "\n")

    if v1_limit is not None:
        v1_dir = tmp_path / "sys_fs_cgroup" / "memory"
        v1_dir.mkdir(parents=True, exist_ok=True)
        (v1_dir / "memory.limit_in_bytes").write_text(str(v1_limit) + "\n")


class TestReadCgroupMemoryLimit:
    """Tests for _read_cgroup_memory_limit()."""

    def test_cgroup_v2_process_specific_path(self, tmp_path):
        """When /proc/self/cgroup points to a service, reads its memory.max."""
        from agent.config import _read_cgroup_memory_limit

        # Create fake cgroup FS
        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/system.slice/edr-agent.service\n")

        service_dir = tmp_path / "cgroup" / "system.slice" / "edr-agent.service"
        service_dir.mkdir(parents=True)
        (service_dir / "memory.max").write_text("4294967296\n")

        # Root cgroup says "max" (no limit)
        cgroup_root = tmp_path / "cgroup"
        (cgroup_root / "memory.max").write_text("max\n")

        real_path = Path

        def mock_path(p):
            if p == "/proc/self/cgroup":
                return real_path(proc_cgroup)
            if p == "/sys/fs/cgroup":
                return real_path(tmp_path / "cgroup")
            if p == "/sys/fs/cgroup/memory.max":
                return real_path(tmp_path / "cgroup" / "memory.max")
            if p == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
                return real_path(tmp_path / "cgroup" / "memory" / "memory.limit_in_bytes")
            return real_path(p)

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result == 4294967296

    def test_cgroup_v2_max_means_no_limit(self, tmp_path):
        from agent.config import _read_cgroup_memory_limit

        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/\n")

        cgroup_root = tmp_path / "cgroup"
        cgroup_root.mkdir(parents=True)
        (cgroup_root / "memory.max").write_text("max\n")

        real_path = Path

        def mock_path(p):
            if p == "/proc/self/cgroup":
                return real_path(proc_cgroup)
            if p == "/sys/fs/cgroup":
                return real_path(tmp_path / "cgroup")
            if p == "/sys/fs/cgroup/memory.max":
                return real_path(tmp_path / "cgroup" / "memory.max")
            if p == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
                raise OSError("no v1")
            return real_path(p)

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result is None

    def test_cgroup_v1_large_value_means_no_limit(self, tmp_path):
        from agent.config import _read_cgroup_memory_limit

        v1_dir = tmp_path / "cgroup" / "memory"
        v1_dir.mkdir(parents=True)
        (v1_dir / "memory.limit_in_bytes").write_text(str(2**63) + "\n")

        real_path = Path

        def mock_path(p):
            if p == "/proc/self/cgroup":
                raise OSError("no proc")
            if p == "/sys/fs/cgroup/memory.max":
                raise OSError("no v2")
            if p == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
                return real_path(v1_dir / "memory.limit_in_bytes")
            return real_path(p)

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result is None

    def test_returns_none_on_macos(self):
        """When no cgroup files exist (e.g. macOS), returns None."""
        from agent.config import _read_cgroup_memory_limit

        def mock_path(p):
            m = MagicMock()
            m.read_text.side_effect = OSError("No such file")
            return m

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result is None

    def test_cgroup_v1_fallback_when_v2_missing(self, tmp_path):
        from agent.config import _read_cgroup_memory_limit

        v1_dir = tmp_path / "cgroup" / "memory"
        v1_dir.mkdir(parents=True)
        (v1_dir / "memory.limit_in_bytes").write_text("2147483648\n")

        real_path = Path

        def mock_path(p):
            if p == "/proc/self/cgroup":
                raise OSError("no proc")
            if p == "/sys/fs/cgroup/memory.max":
                raise OSError("no v2")
            if p == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
                return real_path(v1_dir / "memory.limit_in_bytes")
            return real_path(p)

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result == 2147483648

    def test_cgroup_v2_root_fallback(self, tmp_path):
        """When /proc/self/cgroup is empty path, falls back to root memory.max."""
        from agent.config import _read_cgroup_memory_limit

        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/\n")

        cgroup_root = tmp_path / "cgroup"
        cgroup_root.mkdir(parents=True)
        (cgroup_root / "memory.max").write_text("8589934592\n")  # 8 GB

        real_path = Path

        def mock_path(p):
            if p == "/proc/self/cgroup":
                return real_path(proc_cgroup)
            if p == "/sys/fs/cgroup":
                return real_path(tmp_path / "cgroup")
            if p == "/sys/fs/cgroup/memory.max":
                return real_path(tmp_path / "cgroup" / "memory.max")
            if p == "/sys/fs/cgroup/memory/memory.limit_in_bytes":
                raise OSError("no v1")
            return real_path(p)

        with patch("agent.config.Path", side_effect=mock_path):
            result = _read_cgroup_memory_limit()
            assert result == 8589934592


class TestComputeGraphMemoryMb:
    """Tests for compute_graph_memory_mb()."""

    def test_6pct_of_physical_when_no_cgroup(self):
        """8 GB RAM, no cgroup → 6.25% of 8GB = 512 MB → capped at 256."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 8 * 1024**3  # 8 GB

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=None),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 256  # capped

    def test_6pct_of_cgroup_when_cgroup_smaller(self):
        """40 GB RAM, 4 GB cgroup → 6.25% of 4GB = 256 MB."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 40 * 1024**3  # 40 GB

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=4 * 1024**3),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 256  # 6.25% of 4GB

    def test_floor_at_128mb(self):
        """256 MB RAM → 6.25% = 16 MB → floored at 128."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 256 * 1024**2  # 256 MB

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=None),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 128

    def test_cap_at_256mb(self):
        """64 GB RAM → 6.25% = 4096 MB → capped at 256."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 64 * 1024**3  # 64 GB

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=None),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 256

    def test_cgroup_caps_physical(self):
        """2 GB physical, 1 GB cgroup → 6.25% of 1GB = 64 MB → floored at 128."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 2 * 1024**3

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=1 * 1024**3),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 128  # 6.25% of 1GB = 64, floored at 128

    def test_exact_boundary_2gb(self):
        """2 GB RAM → 6.25% = 128 MB."""
        from agent.config import compute_graph_memory_mb

        mock_vmem = MagicMock()
        mock_vmem.total = 2 * 1024**3

        with (
            patch("agent.config._read_cgroup_memory_limit", return_value=None),
            patch("psutil.virtual_memory", return_value=mock_vmem),
        ):
            result = compute_graph_memory_mb()
            assert result == 128
