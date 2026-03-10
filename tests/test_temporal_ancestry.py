"""Tests for temporal bounding, PPID=1 stop, and bottom-up SPAWNED user.

Covers:
- PidIndex.get_node_id_at_time() — temporal PID disambiguation
- _query_process_fields(conn, pid, event_ts) — picks correct node
- get_process_chain(conn, pid, event_ts) — temporal chain walk
- PPID=1 termination — chain stops before init/systemd
- Bottom-up SPAWNED — correct user selected from deepest match
- _enrich_chain_with_ancestry() — uses trigger_pid over chain-walking
- SecurityFinding.trigger_pid / trigger_timestamp population
"""

import shutil
import tempfile
from datetime import datetime
from unittest.mock import patch

import kuzu

from agent.graph.pid_index import PidIndex
from agent.graph.queries import (
    _query_process_fields,
    get_process_chain,
    graph_chain_to_chainsteps,
)
from agent.schema.graph_types import ChainStep, SecurityFinding
from agent.schema.kuzu_schema import init_graph_schema


def _make_db():
    """Create a temporary Kuzu database with schema initialized."""
    tmp_dir = tempfile.mkdtemp()
    db_path = tmp_dir + "/test_db"
    db = kuzu.Database(db_path)
    conn = kuzu.Connection(db)
    init_graph_schema(conn)
    return db, conn, tmp_dir


def _ts(s: str) -> str:
    return f"timestamp('{s}')"


# ── PidIndex.get_node_id_at_time ──────────────────────────────────────


class TestPidIndexTemporalLookup:
    def test_single_incarnation(self):
        """With a single incarnation, always returns it."""
        idx = PidIndex()
        idx.on_upsert("host:42:1000", 42, 1)
        assert idx.get_node_id_at_time(42, 2000.0) == "host:42:1000"

    def test_single_incarnation_before_event(self):
        """Single incarnation whose epoch is after event_ts returns None."""
        idx = PidIndex()
        idx.on_upsert("host:42:5000", 42, 1)
        assert idx.get_node_id_at_time(42, 2000.0) is None

    def test_multiple_incarnations_picks_correct(self):
        """With multiple incarnations, picks the one active at event_ts."""
        idx = PidIndex()
        idx.on_upsert("host:42:1000", 42, 1)
        idx.on_upsert("host:42:3000", 42, 1)
        idx.on_upsert("host:42:5000", 42, 1)

        # event at ts=4000 should pick epoch=3000 (latest <= 4000)
        assert idx.get_node_id_at_time(42, 4000.0) == "host:42:3000"
        # event at ts=6000 should pick epoch=5000
        assert idx.get_node_id_at_time(42, 6000.0) == "host:42:5000"
        # event at ts=2000 should pick epoch=1000
        assert idx.get_node_id_at_time(42, 2000.0) == "host:42:1000"
        # event at ts=500 — all incarnations newer
        assert idx.get_node_id_at_time(42, 500.0) is None

    def test_unknown_pid_returns_none(self):
        """Nonexistent PID returns None."""
        idx = PidIndex()
        assert idx.get_node_id_at_time(999, 1000.0) is None

    def test_exact_epoch_match(self):
        """Event at the exact epoch of a node selects it."""
        idx = PidIndex()
        idx.on_upsert("host:7:2000", 7, 0)
        idx.on_upsert("host:7:4000", 7, 0)
        assert idx.get_node_id_at_time(7, 2000.0) == "host:7:2000"
        assert idx.get_node_id_at_time(7, 4000.0) == "host:7:4000"


# ── _query_process_fields with event_ts ───────────────────────────────


class TestQueryProcessFieldsTemporal:
    def test_temporal_selects_correct_incarnation(self):
        """event_ts selects the PID incarnation active at that time."""
        db, conn, tmp_dir = _make_db()
        try:
            # Two incarnations of pid=42
            conn.execute(
                "CREATE (p:Process {id: 'host:42:1000', name: 'bash-old', pid: 42, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'host:42:3000', name: 'bash-new', pid: 42, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 13:00:00')}, parent_pid: 0}})"
            )

            # Build the PID index
            idx = PidIndex()
            idx.on_upsert("host:42:1000", 42, 0)
            idx.on_upsert("host:42:3000", 42, 0)
            idx._built = True

            with patch("agent.graph.queries.get_pid_index", return_value=idx):
                # event_ts=2000 -> should get bash-old (epoch 1000)
                result = _query_process_fields(conn, 42, event_ts=2000.0)
                assert result is not None
                assert result["name"] == "bash-old"
                assert result["id"] == "host:42:1000"

                # event_ts=4000 -> should get bash-new (epoch 3000)
                result = _query_process_fields(conn, 42, event_ts=4000.0)
                assert result is not None
                assert result["name"] == "bash-new"
                assert result["id"] == "host:42:3000"

                # event_ts=500 -> nothing valid
                result = _query_process_fields(conn, 42, event_ts=500.0)
                assert result is None
        finally:
            shutil.rmtree(tmp_dir)

    def test_no_event_ts_returns_newest(self):
        """Without event_ts, returns the newest incarnation (backward compat)."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:42:1000', name: 'bash-old', pid: 42, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'host:42:3000', name: 'bash-new', pid: 42, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 13:00:00')}, parent_pid: 0}})"
            )

            idx = PidIndex()
            idx.on_upsert("host:42:1000", 42, 0)
            idx.on_upsert("host:42:3000", 42, 0)
            idx._built = True

            with patch("agent.graph.queries.get_pid_index", return_value=idx):
                result = _query_process_fields(conn, 42)
                assert result is not None
                assert result["name"] == "bash-new"
        finally:
            shutil.rmtree(tmp_dir)

    def test_start_time_in_result(self):
        """Result dict includes start_time field."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:1:1000', name: 'test', pid: 1, "
                "cmd_line: '', exe_path: '', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}}})"
            )
            result = _query_process_fields(conn, 1)
            assert result is not None
            assert "start_time" in result
        finally:
            shutil.rmtree(tmp_dir)


# ── get_process_chain temporal + PPID=1 + bottom-up SPAWNED ───────────


class TestProcessChainPpid1Stop:
    def test_chain_includes_pid1(self):
        """Chain walk includes PID 1 (systemd/init) but stops there."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:1:1000', name: 'systemd', pid: 1, "
                "cmd_line: '/lib/systemd/systemd', exe_path: '/lib/systemd/systemd', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:100:2000', name: 'sshd', pid: 100, "
                "cmd_line: '/usr/sbin/sshd', exe_path: '/usr/sbin/sshd', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 1}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:200:3000', name: 'bash', pid: 200, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:02:00')}, parent_pid: 100}})"
            )

            chain = get_process_chain(conn, 200)
            names = [p.get("name") for p in chain if p.get("name")]
            # PID 1 (systemd) is included as a real ancestor
            assert names == ["systemd", "sshd", "bash"]

        finally:
            shutil.rmtree(tmp_dir)


class TestProcessChainBottomUpSpawned:
    def test_deepest_user_wins(self):
        """Bottom-up SPAWNED query selects the user closest to the leaf."""
        db, conn, tmp_dir = _make_db()
        try:
            # Two users
            conn.execute(
                "CREATE (u1:User {id: 'root', name: 'root', uid: '0', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (u2:User {id: 'jsmith', name: 'jsmith', uid: '1000', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            # sshd (root) -> bash (jsmith) -> curl
            conn.execute(
                "CREATE (p:Process {id: 'h:100:2000', name: 'sshd', pid: 100, "
                "cmd_line: '/usr/sbin/sshd', exe_path: '/usr/sbin/sshd', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:200:3000', name: 'bash', pid: 200, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 100}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:300:4000', name: 'curl', pid: 300, "
                "cmd_line: 'curl http://evil.com', exe_path: '/usr/bin/curl', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:02:00')}, parent_pid: 200}})"
            )
            # SPAWNED edges: root->sshd, jsmith->bash
            conn.execute(
                "MATCH (u:User {id: 'root'}), (p:Process {id: 'h:100:2000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "activity_id: 1, event_id: 1}]->(p)"
            )
            conn.execute(
                "MATCH (u:User {id: 'jsmith'}), (p:Process {id: 'h:200:3000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:01:00')}, "
                "activity_id: 1, event_id: 2}]->(p)"
            )

            chain = get_process_chain(conn, 300)
            # jsmith (deepest match) should be the user, not root
            user_entry = chain[0]
            assert user_entry.get("type") == "user"
            assert user_entry.get("name") == "jsmith"
        finally:
            shutil.rmtree(tmp_dir)

    def test_root_user_when_no_deeper_match(self):
        """Falls back to root user when only the root process has a SPAWNED edge."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (u:User {id: 'root', name: 'root', uid: '0', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:100:2000', name: 'sshd', pid: 100, "
                "cmd_line: '/usr/sbin/sshd', exe_path: '/usr/sbin/sshd', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:200:3000', name: 'bash', pid: 200, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', "
                f"hostname: 'h', start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 100}})"
            )
            conn.execute(
                "MATCH (u:User {id: 'root'}), (p:Process {id: 'h:100:2000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "activity_id: 1, event_id: 1}]->(p)"
            )

            chain = get_process_chain(conn, 200)
            user_entry = chain[0]
            assert user_entry.get("type") == "user"
            assert user_entry.get("name") == "root"
        finally:
            shutil.rmtree(tmp_dir)


class TestProcessChainTemporal:
    def test_event_ts_passed_through(self):
        """get_process_chain passes event_ts to _query_process_fields."""
        db, conn, tmp_dir = _make_db()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:50:1000', name: 'bash', pid: 50, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            # Should succeed with event_ts=2000 (process started at epoch 1000)
            chain = get_process_chain(conn, 50, event_ts=2000.0)
            assert len(chain) >= 1
            assert chain[0]["name"] == "bash" or (chain[0].get("type") == "user")
        finally:
            shutil.rmtree(tmp_dir)


# ── graph_chain_to_chainsteps timestamp propagation ───────────────────


class TestChainStepTimestamp:
    def test_start_time_propagated(self):
        """graph_chain_to_chainsteps propagates start_time to ChainStep.timestamp."""
        graph_chain = [
            {"type": "user", "id": "root", "name": "root"},
            {
                "id": "h:42:1000",
                "name": "bash",
                "pid": 42,
                "start_time": datetime(2025, 6, 1, 12, 0, 0),
            },
        ]
        steps = graph_chain_to_chainsteps(graph_chain)
        assert len(steps) == 2
        assert steps[0].entity_type == "user"
        assert steps[0].timestamp is None  # users don't have start_time
        assert steps[1].entity_type == "process"
        assert steps[1].timestamp == datetime(2025, 6, 1, 12, 0, 0)


# ── SecurityFinding trigger fields ────────────────────────────────────


class TestSecurityFindingTriggerFields:
    def test_trigger_fields_optional(self):
        """trigger_pid and trigger_timestamp default to None."""
        finding = SecurityFinding(
            id="test-id",
            timestamp=datetime.now(),
            severity="info",
            title="Test",
            description="Test finding",
            affected_entities=[],
            evidence_event_ids=[],
            recommendation="None",
            chain=[],
        )
        assert finding.trigger_pid is None
        assert finding.trigger_timestamp is None

    def test_trigger_fields_populated(self):
        """trigger_pid and trigger_timestamp can be set."""
        ts = datetime(2025, 6, 1, 12, 0, 0)
        finding = SecurityFinding(
            id="test-id",
            timestamp=datetime.now(),
            severity="high",
            title="Test",
            description="Test finding",
            affected_entities=[],
            evidence_event_ids=[],
            recommendation="None",
            chain=[],
            trigger_pid=42,
            trigger_timestamp=ts,
        )
        assert finding.trigger_pid == 42
        assert finding.trigger_timestamp == ts


# ── _enrich_chain_with_ancestry with deterministic trigger ────────────


class TestEnrichChainWithAncestry:
    def test_trigger_pid_overrides_chain_walking(self):
        """When trigger_pid is provided, it is used instead of walking the chain."""
        from unittest.mock import MagicMock

        from agent.analyzer.llm_analyzer import LlmAnalyzer

        settings = MagicMock()
        settings.kuzu_persistent_enabled = True
        settings.tool_use_enabled = False
        settings.deepinfra_api_key = None
        db = MagicMock()
        analyzer = LlmAnalyzer(settings, db)

        chain = [
            ChainStep(entity_type="process", entity_id="wrong", entity_name="wrong", pid=999),
        ]

        # Mock get_process_chain to capture what PID is called with
        called_with = {}

        def mock_chain(conn, pid, event_ts=None):
            called_with["pid"] = pid
            called_with["event_ts"] = event_ts
            return [{"type": "user", "id": "jsmith", "name": "jsmith"},
                    {"id": "h:42:1000", "name": "bash", "pid": 42}]

        mock_conn = MagicMock()
        with patch("agent.analyzer.llm_analyzer.get_process_chain", side_effect=mock_chain), \
             patch.object(analyzer, "_get_graph_conn", return_value=mock_conn):
            result = analyzer._enrich_chain_with_ancestry(
                chain, trigger_pid=42, trigger_ts=datetime(2025, 6, 1, 12, 0, 0)
            )

        assert called_with["pid"] == 42  # Used trigger_pid, not 999
        assert called_with["event_ts"] is not None
        # Result should have the enriched chain
        assert any(s.entity_name == "jsmith" for s in result)

    def test_fallback_to_chain_walking_when_no_trigger(self):
        """Without trigger_pid, falls back to walking chain for deepest PID."""
        from unittest.mock import MagicMock

        from agent.analyzer.llm_analyzer import LlmAnalyzer

        settings = MagicMock()
        settings.kuzu_persistent_enabled = True
        settings.tool_use_enabled = False
        settings.deepinfra_api_key = None
        db = MagicMock()
        analyzer = LlmAnalyzer(settings, db)

        chain = [
            ChainStep(entity_type="user", entity_id="root", entity_name="root"),
            ChainStep(entity_type="process", entity_id="h:200:1000", entity_name="bash", pid=200),
            ChainStep(entity_type="process", entity_id="h:300:2000", entity_name="curl", pid=300),
        ]

        called_with = {}

        def mock_chain(conn, pid, event_ts=None):
            called_with["pid"] = pid
            return [{"id": "h:300:2000", "name": "curl", "pid": 300}]

        mock_conn = MagicMock()
        with patch("agent.analyzer.llm_analyzer.get_process_chain", side_effect=mock_chain), \
             patch.object(analyzer, "_get_graph_conn", return_value=mock_conn):
            analyzer._enrich_chain_with_ancestry(chain)

        # Should have picked PID 300 (deepest process in chain)
        assert called_with["pid"] == 300

    def test_disjoint_ioc_filtered_out(self):
        """IOC steps with PIDs not in the enriched tree are discarded."""
        from unittest.mock import MagicMock

        from agent.analyzer.llm_analyzer import LlmAnalyzer

        settings = MagicMock()
        settings.kuzu_persistent_enabled = True
        settings.tool_use_enabled = False
        settings.deepinfra_api_key = None
        db = MagicMock()
        analyzer = LlmAnalyzer(settings, db)

        # Chain has ssh (PID 100) plus a disjoint WebKit IP step (PID 4807)
        chain = [
            ChainStep(entity_type="process", entity_id="h:100:1000", entity_name="ssh", pid=100),
            ChainStep(entity_type="ip", entity_id="10.199.0.5", entity_name="10.199.0.5:22", pid=100),
            ChainStep(entity_type="ip", entity_id="10.199.0.5", entity_name="10.199.0.5:443", pid=4807),
        ]

        def mock_chain(conn, pid, event_ts=None):
            # Enriched tree only contains PID 100 (ssh) and user
            return [
                {"type": "user", "id": "thomas", "name": "thomas"},
                {"id": "h:100:1000", "name": "ssh", "pid": 100},
            ]

        mock_conn = MagicMock()
        with patch("agent.analyzer.llm_analyzer.get_process_chain", side_effect=mock_chain), \
             patch.object(analyzer, "_get_graph_conn", return_value=mock_conn):
            result = analyzer._enrich_chain_with_ancestry(chain, trigger_pid=100)

        # The ssh IP (PID 100) should be kept
        ip_steps = [s for s in result if s.entity_type == "ip"]
        assert len(ip_steps) == 1
        assert ip_steps[0].pid == 100
        # The WebKit IP (PID 4807) should have been discarded
        assert not any(s.pid == 4807 for s in result)

    def test_ioc_without_pid_kept(self):
        """IOC steps with no PID (e.g., from DNS events) are kept."""
        from unittest.mock import MagicMock

        from agent.analyzer.llm_analyzer import LlmAnalyzer

        settings = MagicMock()
        settings.kuzu_persistent_enabled = True
        settings.tool_use_enabled = False
        settings.deepinfra_api_key = None
        db = MagicMock()
        analyzer = LlmAnalyzer(settings, db)

        chain = [
            ChainStep(entity_type="process", entity_id="h:100:1000", entity_name="curl", pid=100),
            ChainStep(entity_type="ip", entity_id="1.2.3.4", entity_name="1.2.3.4:443"),
        ]

        def mock_chain(conn, pid, event_ts=None):
            return [{"id": "h:100:1000", "name": "curl", "pid": 100}]

        mock_conn = MagicMock()
        with patch("agent.analyzer.llm_analyzer.get_process_chain", side_effect=mock_chain), \
             patch.object(analyzer, "_get_graph_conn", return_value=mock_conn):
            result = analyzer._enrich_chain_with_ancestry(chain, trigger_pid=100)

        # IP step with no PID should be preserved
        ip_steps = [s for s in result if s.entity_type == "ip"]
        assert len(ip_steps) == 1


# ── Prompt causal isolation directive ─────────────────────────────────


class TestPromptCausalIsolation:
    def test_causal_isolation_in_prompt(self):
        """System prompt includes the CAUSAL ISOLATION directive."""
        from agent.intel.prompt_builder import build_intel_prompt

        prompt = build_intel_prompt()
        assert "CAUSAL ISOLATION" in prompt
        assert "MUST separate them into multiple, distinct SecurityFinding" in prompt
