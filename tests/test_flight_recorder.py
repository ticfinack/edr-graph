"""Tests for the flight recorder DVR and pull_surveillance_logs handler."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from agent.flight_recorder import FlightRecorder

# ── FlightRecorder unit tests ──


class TestFlightRecorder:
    def test_record_and_query(self, tmp_path):
        """Records are written and queryable."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "process_name": "ssh",
                "pid": 1234,
                "username": "thomas",
                "cmd_line": "ssh root@10.0.0.5",
                "remote_ip": "10.0.0.5",
                "remote_port": 22,
            })
            # Wait for background writer to flush
            time.sleep(1.5)

            rows = recorder.query(ip="10.0.0.5")
            assert len(rows) == 1
            assert rows[0]["process_name"] == "ssh"
            assert rows[0]["remote_ip"] == "10.0.0.5"
            assert rows[0]["remote_port"] == 22
            assert rows[0]["pid"] == 1234
        finally:
            recorder.stop()

    def test_query_filter_by_ip(self, tmp_path):
        """Query filters by IP correctly."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "remote_ip": "10.0.0.5",
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "remote_ip": "10.0.0.6",
            })
            time.sleep(1.5)

            rows_5 = recorder.query(ip="10.0.0.5")
            rows_6 = recorder.query(ip="10.0.0.6")
            assert len(rows_5) == 1
            assert len(rows_6) == 1
            assert rows_5[0]["remote_ip"] == "10.0.0.5"
        finally:
            recorder.stop()

    def test_query_filter_by_username(self, tmp_path):
        """Query filters by username correctly."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "username": "root",
                "process_name": "whoami",
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "username": "thomas",
                "process_name": "ls",
            })
            time.sleep(1.5)

            rows = recorder.query(username="root")
            assert len(rows) == 1
            assert rows[0]["username"] == "root"
            assert rows[0]["process_name"] == "whoami"
        finally:
            recorder.stop()

    def test_query_filter_by_since(self, tmp_path):
        """Query filters by timestamp lower bound."""
        recorder = FlightRecorder(tmp_path)
        try:
            old_ts = time.time() - 3600
            new_ts = time.time()
            recorder.record({"timestamp": old_ts, "event_type": "old", "remote_ip": "10.0.0.1"})
            recorder.record({"timestamp": new_ts, "event_type": "new", "remote_ip": "10.0.0.1"})
            time.sleep(1.5)

            rows = recorder.query(since=new_ts - 1)
            assert len(rows) == 1
            assert rows[0]["event_type"] == "new"
        finally:
            recorder.stop()

    def test_query_limit(self, tmp_path):
        """Query respects the limit parameter."""
        recorder = FlightRecorder(tmp_path)
        try:
            for i in range(10):
                recorder.record({"timestamp": time.time(), "event_type": f"ev{i}", "remote_ip": "10.0.0.1"})
            time.sleep(1.5)

            rows = recorder.query(ip="10.0.0.1", limit=3)
            assert len(rows) == 3
        finally:
            recorder.stop()

    def test_empty_query(self, tmp_path):
        """Query on empty DB returns empty list."""
        recorder = FlightRecorder(tmp_path)
        try:
            rows = recorder.query(ip="192.168.0.1")
            assert rows == []
        finally:
            recorder.stop()

    def test_record_nonblocking_when_full(self, tmp_path):
        """record() doesn't block when the queue is full."""
        recorder = FlightRecorder(tmp_path)
        try:
            # Fill the queue (maxsize=10000) — this should not block
            for _i in range(10_001):
                recorder.record({"timestamp": time.time(), "event_type": "flood", "remote_ip": "10.0.0.1"})
            # If we get here, it didn't block — pass
        finally:
            recorder.stop()

    def test_prune_old_records(self, tmp_path):
        """Records older than TTL are pruned (6h default)."""
        recorder = FlightRecorder(tmp_path)
        try:
            # Insert a record with timestamp 7 hours ago (beyond 6h TTL)
            old_ts = time.time() - (7 * 3600)
            recorder.record({"timestamp": old_ts, "event_type": "old", "remote_ip": "10.0.0.1"})
            recorder.record({"timestamp": time.time(), "event_type": "new", "remote_ip": "10.0.0.1"})
            time.sleep(1.5)

            # Manually trigger prune
            import sqlite3
            conn = sqlite3.connect(str(recorder._db_path))
            recorder._prune(conn)
            conn.close()

            rows = recorder.query(ip="10.0.0.1")
            assert len(rows) == 1
            assert rows[0]["event_type"] == "new"
        finally:
            recorder.stop()

    def test_custom_ttl(self, tmp_path):
        """FlightRecorder respects custom TTL."""
        recorder = FlightRecorder(tmp_path, ttl_hours=1)
        try:
            assert recorder._ttl_seconds == 3600

            # Insert a record 2 hours old (beyond 1h TTL)
            old_ts = time.time() - (2 * 3600)
            recorder.record({"timestamp": old_ts, "event_type": "old", "remote_ip": "10.0.0.1"})
            recorder.record({"timestamp": time.time(), "event_type": "new", "remote_ip": "10.0.0.1"})
            time.sleep(1.5)

            import sqlite3
            conn = sqlite3.connect(str(recorder._db_path))
            recorder._prune(conn)
            conn.close()

            rows = recorder.query(ip="10.0.0.1")
            assert len(rows) == 1
            assert rows[0]["event_type"] == "new"
        finally:
            recorder.stop()

    def test_stop_flushes_remaining(self, tmp_path):
        """stop() flushes remaining queued events."""
        recorder = FlightRecorder(tmp_path)
        # Record without waiting for flush
        recorder.record({"timestamp": time.time(), "event_type": "flush_test", "remote_ip": "10.0.0.1"})
        recorder.stop()

        # Query directly (writer is stopped, use direct SQLite read)
        rows = recorder.query(ip="10.0.0.1")
        assert len(rows) == 1
        assert rows[0]["event_type"] == "flush_test"

    def test_query_uid_alias_matching(self, tmp_path):
        """Query for 'root' also matches rows where username is '0'."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "username": "0",
                "process_name": "bash",
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "username": "root",
                "process_name": "ls",
            })
            time.sleep(1.5)

            rows = recorder.query(username="root")
            assert len(rows) == 2
            usernames = {r["username"] for r in rows}
            assert usernames == {"root", "0"}
        finally:
            recorder.stop()

    def test_query_unknown_username_no_alias(self, tmp_path):
        """Query for non-aliased username uses exact match."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "username": "thomas",
                "process_name": "vim",
            })
            time.sleep(1.5)

            rows = recorder.query(username="1000")
            assert len(rows) == 0

            rows = recorder.query(username="thomas")
            assert len(rows) == 1
        finally:
            recorder.stop()

    def test_squelch_filters_os_noise(self, tmp_path):
        """Query squelches known OS background noise process names."""
        recorder = FlightRecorder(tmp_path)
        try:
            # Squelched: exact match
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "dockerd",
                "pid": 1,
            })
            # Squelched: LIKE pattern
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "kworker/0:1",
                "pid": 2,
            })
            # Squelched: another exact match
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "runningboardd",
                "pid": 3,
            })
            # NOT squelched: legitimate process
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "bash",
                "pid": 100,
            })
            # NOT squelched: process_name is NULL (e.g. network event)
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "remote_ip": "10.0.0.5",
            })
            time.sleep(1.5)

            rows = recorder.query(pids=[1, 2, 3, 100])
            # Only pid 100 (bash) should be returned — others are squelched
            assert len(rows) == 1
            assert rows[0]["pid"] == 100

            # NULL process_name should pass the squelch
            rows_ip = recorder.query(ip="10.0.0.5")
            assert len(rows_ip) == 1
        finally:
            recorder.stop()

    def test_query_filter_by_pids(self, tmp_path):
        """Query filters by PID list correctly."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "bash",
                "pid": 100,
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "ssh",
                "pid": 200,
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "ls",
                "pid": 300,
            })
            time.sleep(1.5)

            rows = recorder.query(pids=[100, 200])
            assert len(rows) == 2
            returned_pids = {r["pid"] for r in rows}
            assert returned_pids == {100, 200}
        finally:
            recorder.stop()

    def test_query_filter_by_pids_combined_with_since(self, tmp_path):
        """Query filters by PIDs + since works together."""
        recorder = FlightRecorder(tmp_path)
        try:
            old_ts = time.time() - 3600
            new_ts = time.time()
            recorder.record({"timestamp": old_ts, "event_type": "old", "pid": 100})
            recorder.record({"timestamp": new_ts, "event_type": "new", "pid": 100})
            recorder.record({"timestamp": new_ts, "event_type": "new2", "pid": 999})
            time.sleep(1.5)

            rows = recorder.query(pids=[100], since=new_ts - 1)
            assert len(rows) == 1
            assert rows[0]["event_type"] == "new"
            assert rows[0]["pid"] == 100
        finally:
            recorder.stop()


# ── DVR recording function tests ──


class TestDvrRecording:
    def _make_entities(self, ips=None, processes=None, users=None, connected_edges=None):
        """Build a minimal entities mock."""
        entities = MagicMock()
        entities.ips = ips or []
        entities.processes = processes or []
        entities.users = users or []
        entities.connected_edges = connected_edges or []
        return entities

    def _make_ip(self, address):
        ip = MagicMock()
        ip.address = address
        ip.id = address
        return ip

    def _make_process(self, name="ssh", pid=1234, cmd_line="ssh root@10.0.0.5"):
        proc = MagicMock()
        proc.name = name
        proc.pid = pid
        proc.cmd_line = cmd_line
        return proc

    def _make_user(self, name="thomas", uid="thomas"):
        user = MagicMock()
        user.name = name
        user.id = uid
        return user

    @patch("agent.main._flight_recorder")
    def test_dvr_records_process_activity(self, mock_recorder):
        """DVR records ProcessActivity unconditionally."""
        from agent.main import _record_to_dvr

        proc = self._make_process(name="whoami", pid=5678, cmd_line="whoami")
        user = self._make_user(name="root", uid="root")
        entities = self._make_entities(processes=[proc], users=[user])

        ocsf = MagicMock()
        type(ocsf).__name__ = "ProcessActivity"

        _record_to_dvr(entities, ocsf)

        mock_recorder.record.assert_called_once()
        call_args = mock_recorder.record.call_args[0][0]
        assert call_args["event_type"] == "ProcessActivity"
        assert call_args["process_name"] == "whoami"
        assert call_args["username"] == "root"

    @patch("agent.main._flight_recorder")
    def test_dvr_records_network_activity_with_ip(self, mock_recorder):
        """DVR records NetworkActivity with IP extraction."""
        from agent.main import _record_to_dvr

        ip = self._make_ip("10.0.0.5")
        proc = self._make_process()
        entities = self._make_entities(
            ips=[ip],
            processes=[proc],
            connected_edges=[{"ip_id": "10.0.0.5", "dst_port": 22}],
        )

        ocsf = MagicMock()
        type(ocsf).__name__ = "NetworkActivity"
        ocsf.dst_endpoint = MagicMock(port=22)

        _record_to_dvr(entities, ocsf)

        mock_recorder.record.assert_called_once()
        call_args = mock_recorder.record.call_args[0][0]
        assert call_args["remote_ip"] == "10.0.0.5"
        assert call_args["remote_port"] == 22
        assert call_args["event_type"] == "NetworkActivity"

    @patch("agent.main._flight_recorder")
    def test_dvr_skips_dns_activity(self, mock_recorder):
        """DVR skips DnsActivity (filtered event type)."""
        from agent.main import _record_to_dvr

        entities = self._make_entities()
        ocsf = MagicMock()
        type(ocsf).__name__ = "DnsActivity"

        _record_to_dvr(entities, ocsf)

        mock_recorder.record.assert_not_called()

    @patch("agent.main._flight_recorder")
    def test_dvr_skips_file_activity(self, mock_recorder):
        """DVR skips FileActivity (filtered event type)."""
        from agent.main import _record_to_dvr

        entities = self._make_entities()
        ocsf = MagicMock()
        type(ocsf).__name__ = "FileActivity"

        _record_to_dvr(entities, ocsf)

        mock_recorder.record.assert_not_called()

    @patch("agent.main._flight_recorder")
    def test_dvr_records_authentication(self, mock_recorder):
        """DVR records Authentication events."""
        from agent.main import _record_to_dvr

        user = self._make_user(name="admin", uid="admin")
        entities = self._make_entities(users=[user])

        ocsf = MagicMock()
        type(ocsf).__name__ = "Authentication"
        ocsf.process = None

        _record_to_dvr(entities, ocsf)

        mock_recorder.record.assert_called_once()
        call_args = mock_recorder.record.call_args[0][0]
        assert call_args["event_type"] == "Authentication"
        assert call_args["username"] == "admin"


# ── pull_surveillance_logs handler tests ──


class TestPullSurveillanceLogs:
    def test_returns_logs(self, tmp_path):
        """Handler returns flight recorder logs for given IPs."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "process_name": "ssh",
                "pid": 1234,
                "remote_ip": "10.0.0.5",
                "remote_port": 22,
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                result = pull_surveillance_logs(None, {"ips": ["10.0.0.5"]})

            assert result["status"] == "ok"
            assert len(result["records"]) == 1
            assert result["records"][0]["remote_ip"] == "10.0.0.5"
        finally:
            recorder.stop()

    def test_returns_logs_by_pids(self, tmp_path):
        """Handler returns flight recorder logs for given anchor_pids."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "bash",
                "pid": 800,
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "ls",
                "pid": 999,
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                # Mock pid_index as not built so it falls through to exact PIDs
                with patch("agent.graph.federated_queries._resolve_descendant_pids",
                           return_value=[800]):
                    result = pull_surveillance_logs(None, {"anchor_pids": [800]})

            assert result["status"] == "ok"
            assert len(result["records"]) == 1
            assert result["records"][0]["pid"] == 800
        finally:
            recorder.stop()

    def test_returns_logs_by_username(self, tmp_path):
        """Handler queries by username (tri-fold: always, not just fallback)."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "whoami",
                "username": "root",
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                result = pull_surveillance_logs(None, {"usernames": ["root"]})

            assert result["status"] == "ok"
            assert len(result["records"]) == 1
            assert result["records"][0]["username"] == "root"
        finally:
            recorder.stop()

    def test_username_query_alongside_pids(self, tmp_path):
        """Handler queries usernames even when anchor_pids are present (tri-fold)."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "cat",
                "pid": 900,
                "username": "root",
            })
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "bash",
                "pid": 800,
                "username": "root",
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                with patch("agent.graph.federated_queries._resolve_descendant_pids",
                           return_value=[800]):
                    result = pull_surveillance_logs(None, {
                        "anchor_pids": [800],
                        "usernames": ["root"],
                    })

            assert result["status"] == "ok"
            # Both records returned (PID 800 from PIDs path, PID 900 from username path), deduplicated
            assert len(result["records"]) == 2
        finally:
            recorder.stop()

    def test_deduplicates_pid_and_ip_matches(self, tmp_path):
        """Handler deduplicates records matched by both PID and IP."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "NetworkActivity",
                "process_name": "ssh",
                "pid": 800,
                "remote_ip": "10.0.0.5",
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                with patch("agent.graph.federated_queries._resolve_descendant_pids",
                           return_value=[800]):
                    result = pull_surveillance_logs(None, {
                        "ips": ["10.0.0.5"],
                        "anchor_pids": [800],
                    })

            assert result["status"] == "ok"
            # Should be 1, not 2 (deduplicated)
            assert len(result["records"]) == 1
        finally:
            recorder.stop()

    def test_returns_empty_for_no_match(self, tmp_path):
        """Handler returns empty records for non-matching IP."""
        recorder = FlightRecorder(tmp_path)
        try:
            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                result = pull_surveillance_logs(None, {"ips": ["10.0.0.99"]})

            assert result["status"] == "ok"
            assert result["records"] == []
        finally:
            recorder.stop()

    def test_returns_error_when_recorder_not_running(self):
        """Handler returns error when no surveillance backend is available."""
        with patch("agent.main._flight_recorder", None), \
             patch("agent.main._ledger_writer", None):
            from agent.graph.federated_queries import pull_surveillance_logs

            result = pull_surveillance_logs(None, {"ips": ["10.0.0.5"]})

        assert result["status"] == "error"
        assert "no surveillance backend" in result.get("error", "")

    def test_returns_logs_by_uid_alias(self, tmp_path):
        """Handler returns logs when UID alias matches (querying 'root' finds '0')."""
        recorder = FlightRecorder(tmp_path)
        try:
            recorder.record({
                "timestamp": time.time(),
                "event_type": "ProcessActivity",
                "process_name": "bash",
                "username": "0",
            })
            time.sleep(1.5)

            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import pull_surveillance_logs

                result = pull_surveillance_logs(None, {"usernames": ["root"]})

            assert result["status"] == "ok"
            assert len(result["records"]) == 1
            assert result["records"][0]["username"] == "0"
        finally:
            recorder.stop()

    def test_dispatches_via_execute_query(self, tmp_path):
        """execute_query dispatches to pull_surveillance_logs handler."""
        recorder = FlightRecorder(tmp_path)
        try:
            with patch("agent.main._flight_recorder", recorder):
                from agent.graph.federated_queries import execute_query

                # Need a dummy Kuzu DB for the dispatch (not used by handler)
                result = execute_query(None, "pull_surveillance_logs", {"ips": []})

            assert result["status"] == "ok"
        finally:
            recorder.stop()


# ── Descendant PID resolution ──


class TestResolveDescendantPids:
    """Test _resolve_descendant_pids BFS via pid_index."""

    def test_resolve_includes_children(self):
        """Anchor PID 800 with children [801, 802] resolves to all three."""
        from agent.graph.federated_queries import _resolve_descendant_pids

        mock_index = MagicMock()
        mock_index.is_built = True
        mock_index.get_children_pids.side_effect = lambda pid: {
            800: [801, 802],
            801: [],
            802: [803],
            803: [],
        }.get(pid, [])

        with patch("agent.graph.pid_index.get_pid_index", return_value=mock_index):
            result = _resolve_descendant_pids([800])

        assert set(result) == {800, 801, 802, 803}

    def test_resolve_returns_anchor_when_index_not_built(self):
        """Falls back to anchor PIDs if index is not built."""
        from agent.graph.federated_queries import _resolve_descendant_pids

        mock_index = MagicMock()
        mock_index.is_built = False

        with patch("agent.graph.pid_index.get_pid_index", return_value=mock_index):
            result = _resolve_descendant_pids([800])

        assert result == [800]

    def test_resolve_empty_input(self):
        """Empty anchor list returns empty."""
        from agent.graph.federated_queries import _resolve_descendant_pids

        result = _resolve_descendant_pids([])
        assert result == []

    def test_resolve_caps_at_max_pids(self):
        """BFS caps at 200 total PIDs."""
        from agent.graph.federated_queries import _resolve_descendant_pids

        mock_index = MagicMock()
        mock_index.is_built = True
        # Each PID spawns 10 children, creating a wide tree
        call_count = [0]

        def mock_children(pid):
            call_count[0] += 1
            if call_count[0] > 250:  # safety
                return []
            return list(range(pid * 10, pid * 10 + 10))

        mock_index.get_children_pids.side_effect = mock_children

        with patch("agent.graph.pid_index.get_pid_index", return_value=mock_index):
            result = _resolve_descendant_pids([1])

        assert len(result) <= 200


# ── SettingsDB surveillance log persistence ──


class TestSettingsDBSurveillance:
    """Test new surveillance tables and methods in SettingsDB."""

    def _make_db(self, tmp_path):
        from server.settings_db import SettingsDB

        return SettingsDB(tmp_path / "test.db")

    def test_upsert_surveillance_logs_dedup(self, tmp_path):
        """Insert twice, count stays same (dedup on original_log_id)."""
        db = self._make_db(tmp_path)
        records = [
            {"id": 1, "timestamp": 1700000000.0, "event_type": "NetworkActivity",
             "process_name": "ssh", "pid": 100, "username": "root",
             "remote_ip": "10.0.0.5", "remote_port": 22},
            {"id": 2, "timestamp": 1700000001.0, "event_type": "ProcessActivity",
             "process_name": "bash", "pid": 101, "username": "root"},
        ]

        count1 = db.upsert_surveillance_logs("inc-1", "agent-dst", "dst", records)
        assert count1 == 2

        count2 = db.upsert_surveillance_logs("inc-1", "agent-dst", "dst", records)
        assert count2 == 0

        db.close()

    def test_get_surveillance_logs_partitions_by_side(self, tmp_path):
        """dst/src correctly partitioned."""
        db = self._make_db(tmp_path)
        dst_records = [
            {"id": 1, "timestamp": 1700000000.0, "event_type": "NetworkActivity",
             "process_name": "sshd"},
        ]
        src_records = [
            {"id": 10, "timestamp": 1700000001.0, "event_type": "ProcessActivity",
             "process_name": "ssh"},
        ]

        db.upsert_surveillance_logs("inc-1", "agent-dst", "dst", dst_records)
        db.upsert_surveillance_logs("inc-1", "agent-src", "src", src_records)

        logs = db.get_surveillance_logs("inc-1")
        assert len(logs["dst_logs"]) == 1
        assert len(logs["src_logs"]) == 1
        assert logs["dst_logs"][0]["process_name"] == "sshd"
        assert logs["src_logs"][0]["process_name"] == "ssh"

        db.close()

    def test_surveillance_pull_state_roundtrip(self, tmp_path):
        """set and get state values."""
        db = self._make_db(tmp_path)

        # Default state
        state = db.get_surveillance_pull_state("inc-1", "dst")
        assert state["last_enqueue_at"] == 0
        assert state["last_record_ts"] == 0.0

        # Set state
        db.set_surveillance_pull_state("inc-1", "dst", last_enqueue_at=1000, last_record_ts=1700000000.0)
        state = db.get_surveillance_pull_state("inc-1", "dst")
        assert state["last_enqueue_at"] == 1000
        assert state["last_record_ts"] == 1700000000.0

        # Update with higher record_ts
        db.set_surveillance_pull_state("inc-1", "dst", last_record_ts=1700000005.0)
        state = db.get_surveillance_pull_state("inc-1", "dst")
        assert state["last_record_ts"] == 1700000005.0

        # Update with lower record_ts — should NOT regress (MAX)
        db.set_surveillance_pull_state("inc-1", "dst", last_record_ts=1700000001.0)
        state = db.get_surveillance_pull_state("inc-1", "dst")
        assert state["last_record_ts"] == 1700000005.0

        db.close()

    def test_complete_xdr_query_returns_metadata(self, tmp_path):
        """complete_xdr_query returns dict with agent_id/finding_id/query_type."""
        db = self._make_db(tmp_path)

        db.enqueue_xdr_query("q-1", "agent-dst", "inc-1:surv_dst", "pull_surveillance_logs", "{}")

        result = db.complete_xdr_query("q-1", '{"records": []}')
        assert result is not None
        assert result["agent_id"] == "agent-dst"
        assert result["finding_id"] == "inc-1:surv_dst"
        assert result["query_type"] == "pull_surveillance_logs"

        # Completing again returns None (already completed)
        result2 = db.complete_xdr_query("q-1", '{"records": []}')
        assert result2 is None

        db.close()

    def test_has_pending_xdr_query(self, tmp_path):
        """has_pending_xdr_query detects pending queries."""
        db = self._make_db(tmp_path)

        assert db.has_pending_xdr_query("inc-1:surv_dst", "pull_surveillance_logs") is False

        db.enqueue_xdr_query("q-2", "agent-dst", "inc-1:surv_dst", "pull_surveillance_logs", "{}")
        assert db.has_pending_xdr_query("inc-1:surv_dst", "pull_surveillance_logs") is True

        db.complete_xdr_query("q-2", '{}')
        assert db.has_pending_xdr_query("inc-1:surv_dst", "pull_surveillance_logs") is False

        db.close()
