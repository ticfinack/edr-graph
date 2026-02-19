"""Response engine orchestrator.

Coordinates response actions: maps severity to actions, checks protected
processes, requests approval, executes actions, and records audit trail.
"""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from agent import metrics
from agent.response.actions import ResponseAction, ResponsePolicy
from agent.response.approval import ApprovalManager, ApprovalStatus
from agent.response.baseline import BehaviorBaseline, ResponseAllowlist
from agent.response.file_quarantine import FileQuarantine, QuarantineResult
from agent.response.network_control import NetworkControlResult, NetworkIsolator
from agent.response.process_control import (
    ProcessControlResult,
    resume_process,
    suspend_process,
    terminate_process,
)

logger = logging.getLogger(__name__)


@dataclass
class ResponseRecord:
    """A single response action record for the audit trail."""

    response_id: str
    event_id: int | None
    timestamp: float
    action_taken: str
    target_pid: int | None = None
    target_path: str | None = None
    llm_severity: str = ""
    llm_confidence: float = 0.0
    approved_by: str = ""
    approval_status: str = "auto"
    result: str = "pending"
    result_detail: str = ""
    reverted: bool = False
    revert_timestamp: float | None = None


class ResponseAuditLog:
    """Append-only audit trail for response actions in SQLite.

    Thread-safe: creates a new connection per operation to avoid
    SQLite's same-thread restriction.
    """

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self._conn = db_conn
        # Store the database path for cross-thread access
        self._db_path: str | None = None
        try:
            row = db_conn.execute("PRAGMA database_list").fetchone()
            if row:
                self._db_path = row[2]  # file path is the 3rd column
        except Exception:
            pass

    def _get_conn(self) -> sqlite3.Connection:
        """Get a SQLite connection safe for the current thread."""
        if self._db_path:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        return self._conn

    def record(self, rec: ResponseRecord) -> None:
        """Insert a response record. Append-only — no updates or deletes."""
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO response_audit "
                "(response_id, event_id, timestamp, action_taken, target_pid, "
                "target_path, llm_severity, llm_confidence, approved_by, "
                "approval_status, result, result_detail, reverted, revert_timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rec.response_id,
                    rec.event_id,
                    _ts_to_iso(rec.timestamp),
                    rec.action_taken,
                    rec.target_pid,
                    rec.target_path,
                    rec.llm_severity,
                    rec.llm_confidence,
                    rec.approved_by,
                    rec.approval_status,
                    rec.result,
                    rec.result_detail,
                    1 if rec.reverted else 0,
                    _ts_to_iso(rec.revert_timestamp) if rec.revert_timestamp else None,
                ),
            )
            conn.commit()
        finally:
            if conn is not self._conn:
                conn.close()

    def get_recent(self, limit: int = 50) -> list[dict]:
        """Get recent audit records."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM response_audit ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            if conn is not self._conn:
                conn.close()

    def get_by_event(self, event_id: int) -> list[dict]:
        """Get all response records for a given event."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM response_audit WHERE event_id = ? ORDER BY timestamp",
                (event_id,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            if conn is not self._conn:
                conn.close()


class ResponseEngine:
    """Orchestrates the full response lifecycle.

    Given a severity verdict from the LLM analyzer, the engine:
    1. Maps severity to response actions via ResponsePolicy
    2. Checks protected process list
    3. Requests approval for destructive actions
    4. Executes approved actions
    5. Records everything in the audit trail
    """

    VALID_MODES = {"learning", "active", "passive"}

    def __init__(
        self,
        policy: ResponsePolicy,
        audit_log: ResponseAuditLog,
        quarantine_dir: Path | None = None,
        baseline: BehaviorBaseline | None = None,
        allowlist: ResponseAllowlist | None = None,
    ) -> None:
        self.policy = policy
        self.audit_log = audit_log
        self.approval_manager = ApprovalManager(policy)
        self.network_isolator = NetworkIsolator()
        self.file_quarantine = FileQuarantine(
            quarantine_dir or Path("/var/edr-graph/quarantine")
        )
        self.baseline = baseline
        self.allowlist = allowlist
        self._response_mode = "passive"
        self.dns_sinkhole = None  # Set after DnsSinkhole is created

    def set_mode(self, mode: str) -> None:
        """Set the response mode. Validates input."""
        if mode not in self.VALID_MODES:
            raise ValueError(f"Invalid mode: {mode!r}. Must be one of {self.VALID_MODES}")
        self._response_mode = mode
        logger.info("Response mode set to: %s", mode)

    @property
    def response_mode(self) -> str:
        return self._response_mode

    def respond(
        self,
        severity: str,
        event_id: int | None = None,
        target_pid: int | None = None,
        target_path: str | None = None,
        process_name: str | None = None,
        confidence: float = 0.0,
        dst_ip: str = "",
        domain: str = "",
        finding_title: str = "",
    ) -> list[ResponseRecord]:
        """Execute the full response pipeline for a severity verdict.

        Returns a list of ResponseRecords documenting each action taken.
        """
        # ── Learning mode: record baseline, never block ──
        if self._response_mode == "learning":
            if self.baseline and process_name:
                target = dst_ip or domain or target_path or "unknown"
                btype = "network" if dst_ip else "dns" if domain else "file"
                self.baseline.record(process_name, btype, target)

            record = ResponseRecord(
                response_id=f"resp-{uuid.uuid4().hex[:12]}",
                event_id=event_id,
                timestamp=time.time(),
                action_taken=ResponseAction.LOG_ONLY.value,
                target_pid=target_pid,
                target_path=target_path,
                llm_severity=severity,
                llm_confidence=confidence,
                result="success",
                approval_status="not_required",
                result_detail="learning mode — behavior recorded",
            )
            self.audit_log.record(record)
            return [record]

        # ── Active mode: check allowlist then baseline ──
        if self._response_mode == "active":
            # Check allowlist
            if self.allowlist:
                matched, desc = self.allowlist.is_allowed(
                    process_name=process_name or "",
                    dst_ip=dst_ip,
                    domain=domain,
                    file_path=target_path or "",
                    finding_title=finding_title,
                )
                if matched:
                    record = ResponseRecord(
                        response_id=f"resp-{uuid.uuid4().hex[:12]}",
                        event_id=event_id,
                        timestamp=time.time(),
                        action_taken=ResponseAction.LOG_ONLY.value,
                        target_pid=target_pid,
                        target_path=target_path,
                        llm_severity=severity,
                        llm_confidence=confidence,
                        result="success",
                        approval_status="not_required",
                        result_detail=f"allowlisted: {desc}",
                    )
                    self.audit_log.record(record)
                    return [record]

            # Check baseline
            if self.baseline and process_name:
                target = dst_ip or domain or target_path or "unknown"
                btype = "network" if dst_ip else "dns" if domain else "file"
                if self.baseline.is_baselined(process_name, btype, target):
                    record = ResponseRecord(
                        response_id=f"resp-{uuid.uuid4().hex[:12]}",
                        event_id=event_id,
                        timestamp=time.time(),
                        action_taken=ResponseAction.LOG_ONLY.value,
                        target_pid=target_pid,
                        target_path=target_path,
                        llm_severity=severity,
                        llm_confidence=confidence,
                        result="success",
                        approval_status="not_required",
                        result_detail="baselined behavior",
                    )
                    self.audit_log.record(record)
                    return [record]

        # ── Passive / Active (non-baselined): normal severity → actions ──
        actions = self.policy.get_actions(severity)
        records: list[ResponseRecord] = []

        for action in actions:
            record = self._execute_action(
                action=action,
                severity=severity,
                event_id=event_id,
                target_pid=target_pid,
                target_path=target_path,
                process_name=process_name,
                confidence=confidence,
                dst_ip=dst_ip,
            )
            records.append(record)

        return records

    def _execute_action(
        self,
        action: ResponseAction,
        severity: str,
        event_id: int | None,
        target_pid: int | None,
        target_path: str | None,
        process_name: str | None,
        confidence: float,
        dst_ip: str = "",
    ) -> ResponseRecord:
        """Execute a single response action with approval and audit."""
        response_id = f"resp-{uuid.uuid4().hex[:12]}"
        now = time.time()

        record = ResponseRecord(
            response_id=response_id,
            event_id=event_id,
            timestamp=now,
            action_taken=action.value,
            target_pid=target_pid,
            target_path=target_path,
            llm_severity=severity,
            llm_confidence=confidence,
        )

        # LOG_ONLY and ALERT don't need approval or execution
        if action == ResponseAction.LOG_ONLY:
            record.result = "success"
            record.approval_status = "not_required"
            self.audit_log.record(record)
            return record

        if action == ResponseAction.ALERT:
            record.result = "success"
            record.approval_status = "not_required"
            logger.warning(
                "ALERT: severity=%s event_id=%s pid=%s — %s",
                severity,
                event_id,
                target_pid,
                target_path or "no path",
            )
            self.audit_log.record(record)
            return record

        # Check protected process list for process-targeting actions
        if action in (ResponseAction.SUSPEND_PROCESS, ResponseAction.TERMINATE_PROCESS):
            if process_name and self.policy.is_protected(process_name):
                record.result = "blocked_protected"
                record.result_detail = f"Process '{process_name}' is protected"
                record.approval_status = "not_required"
                self.audit_log.record(record)
                logger.warning(
                    "Blocked %s on protected process '%s'",
                    action.value,
                    process_name,
                )
                return record

        # Request approval
        approval = self.approval_manager.request_approval(
            action=action,
            target_pid=target_pid,
            target_path=target_path,
            severity=severity,
        )

        if approval.status == ApprovalStatus.AUTO_APPROVED:
            record.approval_status = "auto_approved"
            record.approved_by = approval.approved_by
        elif approval.status == ApprovalStatus.APPROVED:
            record.approval_status = "approved"
            record.approved_by = approval.approved_by
        else:
            # Pending — record as awaiting approval
            record.result = "awaiting_approval"
            record.approval_status = "pending"
            self.audit_log.record(record)
            return record

        # Execute the action
        self._do_execute(action, target_pid, target_path, record, dst_ip=dst_ip)
        self.audit_log.record(record)
        metrics.response_actions_total.labels(
            action=action.value, result=record.result
        ).inc()
        return record

    def _do_execute(
        self,
        action: ResponseAction,
        target_pid: int | None,
        target_path: str | None,
        record: ResponseRecord,
        dst_ip: str = "",
    ) -> None:
        """Actually execute a response action and update the record."""
        if action == ResponseAction.SUSPEND_PROCESS:
            if target_pid is None:
                record.result = "failed"
                record.result_detail = "No target PID provided"
                return
            outcome = suspend_process(target_pid)
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        elif action == ResponseAction.TERMINATE_PROCESS:
            if target_pid is None:
                record.result = "failed"
                record.result_detail = "No target PID provided"
                return
            outcome = terminate_process(target_pid)
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        elif action == ResponseAction.ISOLATE_NETWORK:
            if target_pid is None:
                record.result = "failed"
                record.result_detail = "No target PID provided"
                return
            outcome = self.network_isolator.isolate(target_pid)
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        elif action == ResponseAction.QUARANTINE_FILE:
            if target_path is None:
                record.result = "failed"
                record.result_detail = "No target path provided"
                return
            outcome = self.file_quarantine.quarantine(target_path)
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        elif action == ResponseAction.BLOCK_CONNECTION:
            if not dst_ip:
                record.result = "failed"
                record.result_detail = "No destination IP provided"
                return
            outcome = self.network_isolator.block_connection(dst_ip)
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        elif action == ResponseAction.DNS_SINKHOLE:
            if self.dns_sinkhole is None:
                record.result = "failed"
                record.result_detail = "DNS sinkhole not initialized"
                return
            domain = target_path or ""
            if not domain:
                record.result = "failed"
                record.result_detail = "No domain provided"
                return
            outcome = self.dns_sinkhole.sinkhole(domain)
            record.result = outcome.result
            record.result_detail = outcome.detail

        elif action == ResponseAction.PANIC_ISOLATE:
            outcome = self.network_isolator.panic_isolate()
            record.result = outcome.result.value
            record.result_detail = outcome.detail

        else:
            record.result = "failed"
            record.result_detail = f"Unknown action: {action.value}"


def _ts_to_iso(ts: float) -> str:
    """Convert a Unix timestamp to ISO 8601 string."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
