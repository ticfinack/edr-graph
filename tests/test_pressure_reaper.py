"""Tests for pressure-driven reaper in agent.graph.reaper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


class TestMeasureDbDirSizeMb:
    """Tests for measure_db_dir_size_mb()."""

    def test_measure_empty_dir(self, tmp_path):
        from agent.graph.reaper import measure_db_dir_size_mb

        assert measure_db_dir_size_mb(tmp_path) == 0.0

    def test_measure_directory_with_files(self, tmp_path):
        from agent.graph.reaper import measure_db_dir_size_mb

        graph_dir = tmp_path / "graph"
        graph_dir.mkdir()
        (graph_dir / "file1.dat").write_bytes(b"\x00" * (1024 * 1024))  # 1 MB
        (graph_dir / "subdir").mkdir()
        (graph_dir / "subdir" / "file2.dat").write_bytes(b"\x00" * (512 * 1024))  # 0.5 MB

        size = measure_db_dir_size_mb(graph_dir)
        assert 1.4 < size < 1.6  # ~1.5 MB

    def test_measure_single_file_with_wal(self, tmp_path):
        """Kuzu single-file storage: graph + graph.wal"""
        from agent.graph.reaper import measure_db_dir_size_mb

        graph_file = tmp_path / "graph"
        graph_file.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB
        wal_file = tmp_path / "graph.wal"
        wal_file.write_bytes(b"\x00" * (512 * 1024))  # 0.5 MB

        size = measure_db_dir_size_mb(graph_file)
        assert 2.4 < size < 2.6  # ~2.5 MB

    def test_measure_nonexistent_path(self):
        from agent.graph.reaper import measure_db_dir_size_mb

        result = measure_db_dir_size_mb(Path("/nonexistent/path/that/does/not/exist"))
        assert result == 0.0


class TestPruneEdgesOnly:
    """Tests for prune_edges_only()."""

    def test_prune_edges_only_skips_orphans(self):
        from agent.graph.reaper import prune_edges_only

        mock_conn = MagicMock()

        # Make count queries return 0 (no expired edges)
        mock_result = MagicMock()
        mock_result.has_next.return_value = True
        mock_result.get_next.return_value = [0]
        mock_conn.execute.return_value = mock_result

        result = prune_edges_only(mock_conn, ttl_hours=24)

        # Should have called execute for COUNT queries only (one per edge type)
        # No orphan cleanup queries should appear
        for c in mock_conn.execute.call_args_list:
            query = c[0][0]
            assert "DETACH DELETE" not in query

    def test_prune_edges_only_returns_count(self):
        from agent.graph.reaper import ALL_EDGE_TYPES, prune_edges_only

        mock_conn = MagicMock()

        call_count = 0

        def mock_execute(query, params=None):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if "COUNT" in query and "SPAWNED" in query:
                result.has_next.return_value = True
                result.get_next.return_value = [5]
            elif "COUNT" in query:
                result.has_next.return_value = True
                result.get_next.return_value = [0]
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute

        result = prune_edges_only(mock_conn, ttl_hours=24)
        assert result == 5  # Only SPAWNED had expired edges


class TestBatchedOrphanCleanup:
    """Tests for _cleanup_orphaned_nodes_batched()."""

    def test_batched_orphan_cleanup_deletes_orphans(self):
        """Nodes with zero edges are deleted via DETACH DELETE."""
        from agent.graph.reaper import _cleanup_orphaned_nodes_batched

        mock_conn = MagicMock()
        queries_seen = []

        def mock_execute(query, params=None):
            queries_seen.append(query)
            result = MagicMock()
            if "RETURN n.id SKIP" in query:
                if params and params.get("skip", 0) == 0:
                    # First batch: return 1 node for every type
                    result.has_next.side_effect = [True, False]
                    result.get_next.return_value = ["orphan-1"]
                else:
                    result.has_next.return_value = False
            elif "RETURN COUNT(e)" in query:
                result.has_next.return_value = True
                result.get_next.return_value = [0]
            elif "DETACH DELETE" in query:
                result.has_next.return_value = False
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute
        deleted = _cleanup_orphaned_nodes_batched(mock_conn, batch_size=500)

        # At least some orphans should be deleted
        assert deleted > 0
        # DETACH DELETE should have been called
        delete_queries = [q for q in queries_seen if "DETACH DELETE" in q]
        assert len(delete_queries) > 0

    def test_batched_orphan_keeps_nodes_with_edges(self):
        from agent.graph.reaper import _cleanup_orphaned_nodes_batched

        mock_conn = MagicMock()

        def mock_execute(query, params=None):
            result = MagicMock()
            if "RETURN n.id SKIP" in query and "IP" in query:
                if params and params.get("skip", 0) == 0:
                    result.has_next.side_effect = [True, False]
                    result.get_next.return_value = ["ip1"]
                else:
                    result.has_next.return_value = False
            elif "RETURN n.id SKIP" in query:
                result.has_next.return_value = False
            elif "RETURN COUNT(e)" in query:
                # Has edges — not an orphan
                result.has_next.return_value = True
                result.get_next.return_value = [3]
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute

        deleted = _cleanup_orphaned_nodes_batched(mock_conn, batch_size=500)
        assert deleted == 0


class TestGetRssMb:
    """Tests for get_rss_mb()."""

    def test_get_rss_returns_positive(self):
        from agent.graph.reaper import get_rss_mb

        rss = get_rss_mb()
        assert rss > 0  # We're running, so RSS must be > 0

    def test_get_rss_returns_float(self):
        from agent.graph.reaper import get_rss_mb

        assert isinstance(get_rss_mb(), float)


class TestGetMemoryLimitMb:
    """Tests for get_memory_limit_mb()."""

    def test_memory_limit_returns_positive(self):
        from agent.graph.reaper import get_memory_limit_mb

        limit = get_memory_limit_mb()
        # Should return physical RAM at minimum (no cgroup on macOS dev)
        assert limit > 0

    def test_memory_limit_returns_float(self):
        from agent.graph.reaper import get_memory_limit_mb

        assert isinstance(get_memory_limit_mb(), float)


class TestFractionalTtl:
    """Test that prune functions accept fractional hours (e.g. 5 minutes = 5/60)."""

    def test_prune_edges_with_fractional_ttl(self):
        from agent.graph.reaper import prune_edges_only

        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.has_next.return_value = True
        mock_result.get_next.return_value = [0]
        mock_conn.execute.return_value = mock_result

        # 5 minutes = 5/60 hours
        result = prune_edges_only(mock_conn, ttl_hours=5.0 / 60.0)
        assert result == 0  # No expired edges

    def test_prune_full_with_fractional_ttl(self):
        from agent.graph.reaper import prune_old_edges

        mock_conn = MagicMock()

        def mock_execute(query, params=None):
            result = MagicMock()
            if "COUNT" in query:
                result.has_next.return_value = True
                result.get_next.return_value = [0]
            elif "RETURN n.id SKIP" in query:
                result.has_next.return_value = False
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute

        # 15 minutes = 0.25 hours
        result = prune_old_edges(mock_conn, ttl_hours=0.25)
        assert result == 0


class TestEmergencyThreshold:
    """Test the emergency threshold constant."""

    def test_emergency_threshold_constant(self):
        from agent.graph.reaper import DB_SIZE_EMERGENCY_THRESHOLD_MB

        assert DB_SIZE_EMERGENCY_THRESHOLD_MB == 250


class TestPruneOldEdgesIntegration:
    """Test that prune_old_edges still includes orphan cleanup."""

    def test_prune_old_edges_calls_orphan_cleanup(self):
        from agent.graph.reaper import prune_old_edges

        mock_conn = MagicMock()

        def mock_execute(query, params=None):
            result = MagicMock()
            if "COUNT" in query:
                # Edge count queries return 0 (nothing to prune)
                result.has_next.return_value = True
                result.get_next.return_value = [0]
            elif "RETURN n.id SKIP" in query:
                # Orphan scan queries return empty
                result.has_next.return_value = False
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute

        result = prune_old_edges(mock_conn, ttl_hours=24)

        # Should have called queries including node scan (orphan cleanup)
        all_queries = [c[0][0] for c in mock_conn.execute.call_args_list]
        has_orphan_scan = any("RETURN n.id SKIP" in q for q in all_queries)
        has_count_query = any("COUNT" in q for q in all_queries)
        assert has_count_query
        assert has_orphan_scan
