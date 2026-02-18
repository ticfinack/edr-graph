"""Tests for Phase 3 Commit 3: Network Isolation (3C).

Tests the NetworkIsolator class which manages firewall rules.
Actual firewall commands are mocked since they require root.
"""

from unittest.mock import MagicMock, patch

from agent.response.network_control import (
    NetworkControlOutcome,
    NetworkControlResult,
    NetworkIsolator,
)


class TestNetworkIsolatorState:
    def test_initially_no_pids_isolated(self):
        isolator = NetworkIsolator()
        assert isolator.isolated_pids == set()
        assert not isolator.is_isolated(1234)

    def test_is_isolated_after_isolate(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            isolator.isolate(1234)
        assert isolator.is_isolated(1234)
        assert 1234 in isolator.isolated_pids

    def test_not_isolated_after_restore(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            isolator.isolate(1234)
            isolator.restore(1234)
        assert not isolator.is_isolated(1234)
        assert 1234 not in isolator.isolated_pids

    def test_multiple_pids_tracked(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            isolator.isolate(100)
            isolator.isolate(200)
            isolator.isolate(300)
        assert isolator.isolated_pids == {100, 200, 300}


class TestIsolate:
    def test_isolate_returns_success(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            outcome = isolator.isolate(1234)
        assert outcome.result == NetworkControlResult.SUCCESS
        assert outcome.pid == 1234
        assert outcome.action == "isolate"
        assert len(outcome.rules_applied) > 0

    def test_isolate_already_isolated(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            isolator.isolate(1234)
            outcome = isolator.isolate(1234)
        assert outcome.result == NetworkControlResult.ALREADY_ISOLATED
        assert outcome.pid == 1234

    def test_isolate_command_failure(self):
        isolator = NetworkIsolator()
        with patch(
            "agent.response.network_control._run_command",
            side_effect=RuntimeError("pfctl failed"),
        ):
            outcome = isolator.isolate(1234)
        assert outcome.result == NetworkControlResult.FAILED
        assert "pfctl failed" in outcome.detail

    def test_isolate_permission_denied(self):
        isolator = NetworkIsolator()
        with patch(
            "agent.response.network_control._run_command",
            side_effect=PermissionError("not root"),
        ):
            outcome = isolator.isolate(1234)
        assert outcome.result == NetworkControlResult.PERMISSION_DENIED


class TestRestore:
    def test_restore_returns_success(self):
        isolator = NetworkIsolator()
        with patch("agent.response.network_control._run_command"):
            isolator.isolate(1234)
            outcome = isolator.restore(1234)
        assert outcome.result == NetworkControlResult.SUCCESS
        assert outcome.pid == 1234
        assert outcome.action == "restore"

    def test_restore_not_isolated(self):
        isolator = NetworkIsolator()
        outcome = isolator.restore(9999)
        assert outcome.result == NetworkControlResult.NOT_ISOLATED
        assert outcome.pid == 9999

    def test_restore_partial_failure(self):
        """If rule deletion fails, the PID is still un-tracked but result is FAILED."""
        isolator = NetworkIsolator()
        isolate_done = False

        def mock_run(cmd, **kwargs):
            nonlocal isolate_done
            if not isolate_done:
                return  # Isolate calls succeed
            raise RuntimeError("delete failed")

        with patch("agent.response.network_control._run_command", side_effect=mock_run):
            isolator.isolate(1234)
            isolate_done = True
            outcome = isolator.restore(1234)
        assert outcome.result == NetworkControlResult.FAILED
        assert not isolator.is_isolated(1234)  # Still un-tracked


class TestNetworkControlOutcome:
    def test_outcome_fields(self):
        outcome = NetworkControlOutcome(
            result=NetworkControlResult.SUCCESS,
            pid=42,
            action="isolate",
            rules_applied=["rule1", "rule2"],
            detail="test",
        )
        assert outcome.result == NetworkControlResult.SUCCESS
        assert outcome.pid == 42
        assert outcome.action == "isolate"
        assert outcome.rules_applied == ["rule1", "rule2"]
        assert outcome.detail == "test"

    def test_outcome_defaults(self):
        outcome = NetworkControlOutcome(
            result=NetworkControlResult.FAILED,
            pid=0,
            action="restore",
        )
        assert outcome.rules_applied == []
        assert outcome.detail == ""


class TestNetworkControlResultEnum:
    def test_all_values(self):
        assert NetworkControlResult.SUCCESS.value == "success"
        assert NetworkControlResult.NOT_FOUND.value == "not_found"
        assert NetworkControlResult.PERMISSION_DENIED.value == "permission_denied"
        assert NetworkControlResult.FAILED.value == "failed"
        assert NetworkControlResult.ALREADY_ISOLATED.value == "already_isolated"
        assert NetworkControlResult.NOT_ISOLATED.value == "not_isolated"
