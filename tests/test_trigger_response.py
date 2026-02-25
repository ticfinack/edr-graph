"""Tests for _trigger_response and graph_chain_to_chainsteps."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from agent.graph.queries import graph_chain_to_chainsteps
from agent.main import _trigger_response
from agent.response.baseline import _extract_chain_names
from agent.schema.graph_types import ChainStep, SecurityFinding
from agent.schema.ocsf_types import DeviceInfo, ProcessActivity, ProcessInfo


def _make_finding(chain=None, pids=None, severity="high"):
    """Build a minimal SecurityFinding for testing."""
    return SecurityFinding(
        id="test-finding-1",
        timestamp=datetime.now(),
        severity=severity,
        title="Test finding",
        description="test",
        affected_entities=["test"],
        evidence_event_ids=[42],
        recommendation="investigate",
        chain=chain or [],
        affected_pids=pids or [],
    )


# ── graph_chain_to_chainsteps ──


class TestGraphChainToChainsteps:
    def test_chainsteps_user_entry(self):
        """User dict → ChainStep with entity_type='user'."""
        graph_chain = [{"type": "user", "id": "root", "name": "root"}]
        steps = graph_chain_to_chainsteps(graph_chain)
        assert len(steps) == 1
        assert steps[0].entity_type == "user"
        assert steps[0].entity_name == "root"

    def test_chainsteps_process_entry(self):
        """Process dict → ChainStep with entity_type='process' and correct pid."""
        graph_chain = [{"id": "host:100:1000", "name": "bash", "pid": 100, "parent_pid": 1}]
        steps = graph_chain_to_chainsteps(graph_chain)
        assert len(steps) == 1
        assert steps[0].entity_type == "process"
        assert steps[0].entity_name == "bash"
        assert steps[0].pid == 100

    def test_chainsteps_full_chain_names(self):
        """Full graph chain → _extract_chain_names returns correct names."""
        graph_chain = [
            {"type": "user", "id": "root", "name": "root"},
            {"id": "host:1:1000", "name": "systemd", "pid": 1, "parent_pid": 0},
            {"id": "host:100:2000", "name": "bash", "pid": 100, "parent_pid": 1},
        ]
        steps = graph_chain_to_chainsteps(graph_chain)
        names = _extract_chain_names(steps)
        assert names == ["USER:root", "systemd", "bash"]


# ── _trigger_response with graph chain ──


def _make_process_event(pid=100, name="bash"):
    """Build a minimal ProcessActivity for testing."""
    return ProcessActivity(
        process=ProcessInfo(pid=pid, name=name),
        activity_id=1,
        time=datetime.now(),
        device=DeviceInfo(hostname="test-host"),
    )


class TestTriggerResponseGraphChain:
    def test_uses_graph_chain(self):
        """When kuzu_db is provided and graph returns chain, use it instead of finding.chain."""
        finding_chain = [
            ChainStep(entity_type="process", entity_id="llm-derived", entity_name="wrong"),
        ]
        finding = _make_finding(chain=finding_chain, pids=[100])

        graph_chain_result = [
            {"type": "user", "id": "root", "name": "root"},
            {"id": "host:1:1000", "name": "systemd", "pid": 1, "parent_pid": 0},
            {"id": "host:100:2000", "name": "bash", "pid": 100, "parent_pid": 1},
        ]

        mock_engine = MagicMock()
        mock_engine.respond.return_value = []
        mock_kuzu_db = MagicMock()
        event = _make_process_event(pid=100, name="bash")

        with patch("agent.main.get_connection", return_value=MagicMock()), \
             patch("agent.graph.queries.get_process_chain", return_value=graph_chain_result):
            _trigger_response(mock_engine, finding, [(42, event)], kuzu_db=mock_kuzu_db)

        # Verify engine.respond was called with graph-derived chain
        call_kwargs = mock_engine.respond.call_args
        chain_arg = call_kwargs.kwargs.get("chain") or call_kwargs[1].get("chain")
        assert len(chain_arg) == 3
        assert chain_arg[0].entity_type == "user"
        assert chain_arg[0].entity_name == "root"
        assert chain_arg[2].entity_name == "bash"

    def test_fallback_to_finding_chain_when_no_db(self):
        """When kuzu_db=None, uses finding.chain."""
        finding_chain = [
            ChainStep(entity_type="process", entity_id="original", entity_name="original_proc"),
        ]
        finding = _make_finding(chain=finding_chain, pids=[100])

        mock_engine = MagicMock()
        mock_engine.respond.return_value = []
        event = _make_process_event(pid=100, name="bash")

        _trigger_response(mock_engine, finding, [(42, event)], kuzu_db=None)

        call_kwargs = mock_engine.respond.call_args
        chain_arg = call_kwargs.kwargs.get("chain") or call_kwargs[1].get("chain")
        assert chain_arg == finding_chain

    def test_fallback_on_graph_error(self):
        """When graph lookup raises, falls back to finding.chain."""
        finding_chain = [
            ChainStep(entity_type="process", entity_id="fallback", entity_name="fallback_proc"),
        ]
        finding = _make_finding(chain=finding_chain, pids=[100])

        mock_engine = MagicMock()
        mock_engine.respond.return_value = []
        mock_kuzu_db = MagicMock()
        event = _make_process_event(pid=100, name="bash")

        with patch("agent.main.kuzu") as mock_kuzu_mod:
            mock_kuzu_mod.Connection.return_value = MagicMock()
            with patch("agent.graph.queries.get_process_chain", side_effect=RuntimeError("db error")):
                _trigger_response(mock_engine, finding, [(42, event)], kuzu_db=mock_kuzu_db)

        call_kwargs = mock_engine.respond.call_args
        chain_arg = call_kwargs.kwargs.get("chain") or call_kwargs[1].get("chain")
        assert chain_arg == finding_chain
