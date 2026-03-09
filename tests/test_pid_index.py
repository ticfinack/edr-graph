"""Tests for PID index garbage collection, self-healing, and PID wraparound."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent.graph.pid_index import PidIndex

# ── Helpers ──────────────────────────────────────────────────────────────


def _build_index(*entries) -> PidIndex:
    """Build a PidIndex from (node_id, pid, parent_pid[, name]) tuples."""
    idx = PidIndex()
    idx._built = True
    for entry in entries:
        if len(entry) == 4:
            node_id, pid, ppid, name = entry
            idx.on_upsert(node_id, pid, ppid, name)
        else:
            node_id, pid, ppid = entry
            idx.on_upsert(node_id, pid, ppid)
    return idx


# ── TestRemoveNodes ──────────────────────────────────────────────────────


class TestRemoveNodes:
    def test_evicts_matching_node_ids(self):
        idx = _build_index(
            ("host:100:1000", 100, 1),
            ("host:100:2000", 100, 1),
            ("host:200:3000", 200, 1),
        )
        evicted = idx.remove_nodes(["host:100:1000"])
        assert evicted == 1
        assert idx.get_node_ids(100) == ["host:100:2000"]
        assert idx.get_node_ids(200) == ["host:200:3000"]

    def test_cleans_empty_pid_bucket(self):
        idx = _build_index(
            ("host:100:1000", 100, 1),
        )
        evicted = idx.remove_nodes(["host:100:1000"])
        assert evicted == 1
        assert idx.get_node_ids(100) == []

    def test_cleans_ppid_to_children_when_pid_removed(self):
        """When all node_ids for a PID are removed, that PID should be
        pruned from the ppid_to_children mapping too."""
        idx = _build_index(
            ("host:100:1000", 100, 1),  # pid=100, parent=1
            ("host:200:2000", 200, 1),  # pid=200, parent=1
        )
        # Both 100 and 200 are children of ppid=1
        assert 100 in set(idx.get_children_pids(1))
        assert 200 in set(idx.get_children_pids(1))

        idx.remove_nodes(["host:100:1000"])
        children = set(idx.get_children_pids(1))
        assert 100 not in children
        assert 200 in children

    def test_cleans_empty_ppid_group(self):
        """When all children of a ppid are removed, the ppid entry is deleted."""
        idx = _build_index(
            ("host:100:1000", 100, 50),
        )
        assert idx.get_children_pids(50) == [100]
        idx.remove_nodes(["host:100:1000"])
        assert idx.get_children_pids(50) == []
        # Internal: ppid 50 should be completely gone
        assert 50 not in idx._ppid_to_children

    def test_no_op_on_empty_list(self):
        idx = _build_index(("host:100:1000", 100, 1))
        assert idx.remove_nodes([]) == 0
        assert idx.get_node_ids(100) == ["host:100:1000"]

    def test_no_op_on_unknown_ids(self):
        idx = _build_index(("host:100:1000", 100, 1))
        assert idx.remove_nodes(["host:999:9999"]) == 0
        assert idx.get_node_ids(100) == ["host:100:1000"]

    def test_batch_eviction(self):
        idx = _build_index(
            ("host:100:1000", 100, 1),
            ("host:100:2000", 100, 1),
            ("host:200:3000", 200, 1),
        )
        evicted = idx.remove_nodes(["host:100:1000", "host:200:3000"])
        assert evicted == 2
        assert idx.get_node_ids(100) == ["host:100:2000"]
        assert idx.get_node_ids(200) == []


# ── TestPidWraparound ────────────────────────────────────────────────────


class TestPidWraparound:
    def test_get_latest_returns_highest_epoch(self):
        idx = _build_index(
            ("host:100:5000.0", 100, 1),
            ("host:100:1000.0", 100, 1),
            ("host:100:9000.0", 100, 1),
        )
        assert idx.get_latest_node_id(100) == "host:100:9000.0"

    def test_get_node_ids_sorted_newest_first(self):
        idx = _build_index(
            ("host:100:5000.0", 100, 1),
            ("host:100:1000.0", 100, 1),
            ("host:100:9000.0", 100, 1),
        )
        ids = idx.get_node_ids(100)
        assert ids == ["host:100:9000.0", "host:100:5000.0", "host:100:1000.0"]

    def test_single_entry_no_sort(self):
        idx = _build_index(("host:100:5000.0", 100, 1))
        assert idx.get_latest_node_id(100) == "host:100:5000.0"
        assert idx.get_node_ids(100) == ["host:100:5000.0"]

    def test_missing_pid_returns_none(self):
        idx = _build_index()
        assert idx.get_latest_node_id(999) is None
        assert idx.get_node_ids(999) == []

    def test_extract_epoch_with_colons_in_hostname(self):
        """Hostnames with colons (e.g. IPv6) should not break epoch parsing."""
        assert PidIndex._extract_epoch("host:with:colons:100:1234.5") == 1234.5

    def test_extract_epoch_malformed(self):
        assert PidIndex._extract_epoch("malformed") == 0.0
        assert PidIndex._extract_epoch("") == 0.0


# ── TestSelfHealing ──────────────────────────────────────────────────────


class TestSelfHealing:
    def test_query_process_fields_evicts_stale(self):
        """When _query_process_fields hits a stale node_id (Kuzu returns
        empty), the stale entry should be evicted from the PID index."""
        idx = _build_index(
            ("host:100:2000.0", 100, 1),  # stale — will return empty
            ("host:100:1000.0", 100, 1),  # also stale
        )

        # Mock Kuzu connection that returns empty for all queries
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.has_next.return_value = False
        mock_conn.execute.return_value = mock_result

        with patch("agent.graph.queries.get_pid_index", return_value=idx):
            from agent.graph.queries import _query_process_fields

            result = _query_process_fields(mock_conn, 100)

        assert result is None
        # Both stale entries should have been evicted
        assert idx.get_node_ids(100) == []

    def test_query_process_fields_evicts_stale_before_hit(self):
        """If the first node_id is stale but a later one is valid,
        the stale one should still be evicted."""
        idx = _build_index(
            ("host:100:2000.0", 100, 1),  # newest — stale
            ("host:100:1000.0", 100, 1),  # older — valid
        )

        call_count = 0

        def mock_execute(query, params=None):
            nonlocal call_count
            call_count += 1
            mock_result = MagicMock()
            nid = params.get("id") if params else None
            if nid == "host:100:1000.0":
                # This one exists — return a row
                mock_result.has_next.return_value = True
                mock_result.get_next.return_value = [
                    "host:100:1000.0",
                    "bash",
                    100,
                    "/bin/bash",
                    "/bin/bash",
                    "host",
                    1,
                    None,
                    True,
                    "Apple",
                    None,  # start_time
                ]
            else:
                # Stale
                mock_result.has_next.return_value = False
            return mock_result

        mock_conn = MagicMock()
        mock_conn.execute.side_effect = mock_execute

        with patch("agent.graph.queries.get_pid_index", return_value=idx):
            from agent.graph.queries import _query_process_fields

            result = _query_process_fields(mock_conn, 100)

        assert result is not None
        assert result["id"] == "host:100:1000.0"
        # The stale entry should have been evicted
        assert idx.get_node_ids(100) == ["host:100:1000.0"]

    def test_get_process_children_evicts_stale(self):
        """get_process_children should evict stale child node_ids."""
        idx = _build_index(
            ("host:100:1000.0", 100, 1),
            ("host:200:2000.0", 200, 100),  # child of 100 — stale
        )

        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.has_next.return_value = False
        mock_conn.execute.return_value = mock_result

        with patch("agent.graph.queries.get_pid_index", return_value=idx):
            from agent.graph.queries import get_process_children

            children = get_process_children(mock_conn, 100)

        assert children == []
        # Stale child entry should have been evicted
        assert idx.get_node_ids(200) == []


# ── TestReaperSync ───────────────────────────────────────────────────────


class TestReaperSync:
    def test_cleanup_orphaned_nodes_syncs_pid_index(self):
        """_cleanup_orphaned_nodes_batched calls remove_nodes on the PID index
        when Process nodes are deleted."""
        mock_conn = MagicMock()

        def mock_execute(query, params=None):
            result = MagicMock()
            if "RETURN n.id SKIP" in query and "Process" in query:
                if params and params.get("skip", 0) == 0:
                    # First batch: one Process node
                    result.has_next.side_effect = [True, False]
                    result.get_next.return_value = ["host:100:1000"]
                else:
                    result.has_next.return_value = False
            elif "RETURN n.id SKIP" in query:
                # Other node types: no nodes
                result.has_next.return_value = False
            elif "RETURN COUNT(e)" in query:
                # No edges (orphan)
                result.has_next.return_value = True
                result.get_next.return_value = [0]
            elif "DETACH DELETE" in query:
                result.has_next.return_value = False
            else:
                result.has_next.return_value = False
            return result

        mock_conn.execute.side_effect = mock_execute

        mock_idx = MagicMock()
        mock_idx.remove_nodes.return_value = 1

        with patch("agent.graph.reaper.get_pid_index", return_value=mock_idx):
            from agent.graph.reaper import _cleanup_orphaned_nodes_batched

            deleted = _cleanup_orphaned_nodes_batched(mock_conn)

        # At least 1 Process node deleted
        assert deleted >= 1
        # remove_nodes should have been called with the deleted Process ID
        mock_idx.remove_nodes.assert_called_once()
        call_args = mock_idx.remove_nodes.call_args[0][0]
        assert "host:100:1000" in call_args


# ── TestParentAndNameLookup ─────────────────────────────────────────────


class TestParentAndNameLookup:
    def test_on_upsert_stores_ppid_and_name(self):
        idx = _build_index(("host:100:1000", 100, 50, "bash"))
        assert idx.get_parent_pid(100) == 50
        assert idx.get_name(100) == "bash"

    def test_on_upsert_default_name(self):
        idx = _build_index(("host:100:1000", 100, 50))
        assert idx.get_parent_pid(100) == 50
        assert idx.get_name(100) == ""

    def test_remove_nodes_cleans_ppid_and_name(self):
        idx = _build_index(("host:100:1000", 100, 50, "bash"))
        assert idx.get_parent_pid(100) == 50
        assert idx.get_name(100) == "bash"
        idx.remove_nodes(["host:100:1000"])
        assert idx.get_parent_pid(100) is None
        assert idx.get_name(100) == ""

    def test_get_parent_pid_returns_none_for_root(self):
        """ppid=0 means root/unknown — get_parent_pid should return None."""
        idx = _build_index(("host:1:1000", 1, 0, "launchd"))
        assert idx.get_parent_pid(1) is None
