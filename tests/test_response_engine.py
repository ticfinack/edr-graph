"""Tests for Phase 3 Commit 5: Approval Workflow, Audit Trail, and Response Engine (3E+3F)."""

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.response.actions import ResponseAction, ResponsePolicy
from agent.response.approval import ApprovalManager, ApprovalRequest, ApprovalStatus
from agent.response.engine import ResponseAuditLog, ResponseEngine, ResponseRecord
from agent.schema.queue_schema import init_queue_db


@pytest.fixture
def db_conn():
    """In-memory SQLite connection with schema initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_queue_db(conn)
    yield conn
    conn.close()


@pytest.fixture
def audit_log(db_conn):
    return ResponseAuditLog(db_conn)


@pytest.fixture
def engine(audit_log, tmp_path):
    policy = ResponsePolicy(auto_respond=False)
    return ResponseEngine(policy, audit_log, quarantine_dir=tmp_path / "quarantine")


@pytest.fixture
def auto_engine(audit_log, tmp_path):
    policy = ResponsePolicy(auto_respond=True, auto_terminate=False)
    return ResponseEngine(policy, audit_log, quarantine_dir=tmp_path / "quarantine")


# --- ApprovalManager tests ---


class TestApprovalManager:
    def test_auto_approve_when_policy_allows(self):
        policy = ResponsePolicy(auto_respond=True)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.SUSPEND_PROCESS, target_pid=123)
        assert req.status == ApprovalStatus.AUTO_APPROVED
        assert req.approved_by == "policy:auto_respond"

    def test_pending_when_approval_required(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.SUSPEND_PROCESS, target_pid=123)
        assert req.status == ApprovalStatus.PENDING
        assert len(mgr.pending_requests) == 1

    def test_approve_pending_request(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.ISOLATE_NETWORK, target_pid=456)
        result = mgr.approve(req.request_id, approved_by="admin")
        assert result is not None
        assert result.status == ApprovalStatus.APPROVED
        assert result.approved_by == "admin"
        assert len(mgr.pending_requests) == 0

    def test_deny_pending_request(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.TERMINATE_PROCESS, target_pid=789)
        result = mgr.deny(req.request_id, denied_by="security_team")
        assert result is not None
        assert result.status == ApprovalStatus.DENIED
        assert len(mgr.pending_requests) == 0

    def test_approve_nonexistent_returns_none(self):
        policy = ResponsePolicy()
        mgr = ApprovalManager(policy)
        assert mgr.approve("nonexistent-id") is None

    def test_deny_nonexistent_returns_none(self):
        policy = ResponsePolicy()
        mgr = ApprovalManager(policy)
        assert mgr.deny("nonexistent-id") is None

    def test_history_tracks_resolved(self):
        policy = ResponsePolicy(auto_respond=True)
        mgr = ApprovalManager(policy)
        mgr.request_approval(ResponseAction.SUSPEND_PROCESS, target_pid=1)
        mgr.request_approval(ResponseAction.ISOLATE_NETWORK, target_pid=2)
        assert len(mgr.history) == 2

    def test_is_approved_auto(self):
        policy = ResponsePolicy(auto_respond=True)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.SUSPEND_PROCESS)
        assert mgr.is_approved(req.request_id)

    def test_is_approved_manual(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.SUSPEND_PROCESS)
        mgr.approve(req.request_id)
        assert mgr.is_approved(req.request_id)

    def test_is_approved_denied(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.SUSPEND_PROCESS)
        mgr.deny(req.request_id)
        assert not mgr.is_approved(req.request_id)

    def test_log_and_alert_no_approval_needed(self):
        policy = ResponsePolicy(auto_respond=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.LOG_ONLY)
        assert req.status == ApprovalStatus.AUTO_APPROVED

    def test_terminate_requires_both_flags(self):
        policy = ResponsePolicy(auto_respond=True, auto_terminate=False)
        mgr = ApprovalManager(policy)
        req = mgr.request_approval(ResponseAction.TERMINATE_PROCESS, target_pid=1)
        assert req.status == ApprovalStatus.PENDING


# --- ResponseAuditLog tests ---


class TestResponseAuditLog:
    def test_record_and_retrieve(self, audit_log):
        rec = ResponseRecord(
            response_id="resp-test-001",
            event_id=42,
            timestamp=1700000000.0,
            action_taken="log_only",
            llm_severity="info",
            result="success",
        )
        audit_log.record(rec)
        rows = audit_log.get_recent(limit=10)
        assert len(rows) == 1
        assert rows[0]["response_id"] == "resp-test-001"
        assert rows[0]["event_id"] == 42
        assert rows[0]["action_taken"] == "log_only"

    def test_get_by_event(self, audit_log):
        for i in range(3):
            audit_log.record(
                ResponseRecord(
                    response_id=f"resp-{i}",
                    event_id=100,
                    timestamp=1700000000.0 + i,
                    action_taken="alert",
                    result="success",
                )
            )
        audit_log.record(
            ResponseRecord(
                response_id="resp-other",
                event_id=200,
                timestamp=1700000000.0,
                action_taken="log_only",
                result="success",
            )
        )
        rows = audit_log.get_by_event(100)
        assert len(rows) == 3

    def test_append_only(self, audit_log):
        """Records accumulate — no overwrites."""
        for i in range(5):
            audit_log.record(
                ResponseRecord(
                    response_id=f"resp-{i}",
                    event_id=i,
                    timestamp=1700000000.0,
                    action_taken="log_only",
                    result="success",
                )
            )
        assert len(audit_log.get_recent(limit=100)) == 5


# --- ResponseEngine tests ---


class TestResponseEngineInfoSeverity:
    def test_info_logs_only(self, engine):
        records = engine.respond(severity="info", event_id=1)
        assert len(records) == 1
        assert records[0].action_taken == "log_only"
        assert records[0].result == "success"

    def test_low_logs_only(self, engine):
        records = engine.respond(severity="low", event_id=2)
        assert len(records) == 1
        assert records[0].action_taken == "log_only"


class TestResponseEngineMediumSeverity:
    def test_medium_alerts(self, engine):
        records = engine.respond(severity="medium", event_id=3)
        assert len(records) == 1
        assert records[0].action_taken == "alert"
        assert records[0].result == "success"


class TestResponseEngineHighSeverity:
    def test_high_without_auto_respond_pends_block_connection(self, engine):
        records = engine.respond(severity="high", event_id=4, target_pid=1234, dst_ip="1.2.3.4")
        actions = [r.action_taken for r in records]
        assert "alert" in actions
        assert "block_connection" in actions
        # Block should be awaiting approval (auto_respond=False)
        block_rec = [r for r in records if r.action_taken == "block_connection"][0]
        assert block_rec.result == "awaiting_approval"

    def test_high_with_auto_respond_executes(self, auto_engine):
        with patch("agent.response.network_control._run_command"):
            records = auto_engine.respond(severity="high", event_id=5, target_pid=1234, dst_ip="1.2.3.4")
        block_rec = [r for r in records if r.action_taken == "block_connection"][0]
        assert block_rec.result == "success"
        assert block_rec.approval_status == "auto_approved"


class TestResponseEngineCriticalSeverity:
    def test_critical_blocks_protected_process(self, auto_engine):
        records = auto_engine.respond(
            severity="critical",
            event_id=6,
            target_pid=1,
            process_name="csrss.exe",
        )
        suspend_rec = [r for r in records if r.action_taken == "suspend_process"][0]
        assert suspend_rec.result == "blocked_protected"

    def test_critical_without_pid_fails(self, auto_engine):
        with patch("agent.response.network_control._run_command"):
            records = auto_engine.respond(severity="critical", event_id=7)
        suspend_rec = [r for r in records if r.action_taken == "suspend_process"][0]
        assert suspend_rec.result == "failed"
        assert "No target PID" in suspend_rec.result_detail


class TestResponseEngineAuditTrail:
    def test_all_actions_recorded_in_audit(self, engine, audit_log):
        engine.respond(severity="info", event_id=10)
        engine.respond(severity="medium", event_id=11)
        records = audit_log.get_recent(limit=100)
        assert len(records) == 2

    def test_audit_records_have_timestamps(self, engine, audit_log):
        engine.respond(severity="info", event_id=20)
        records = audit_log.get_recent()
        assert records[0]["timestamp"] is not None
        assert records[0]["response_id"].startswith("resp-")
