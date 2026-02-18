"""Human-in-the-loop approval for destructive response actions.

Queues approval requests for actions that require confirmation.
Supports auto-approve based on policy flags.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum

from agent.response.actions import ResponseAction, ResponsePolicy

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    AUTO_APPROVED = "auto_approved"


@dataclass
class ApprovalRequest:
    """A request for human approval of a response action."""

    request_id: str
    action: ResponseAction
    target_pid: int | None = None
    target_path: str | None = None
    severity: str = ""
    reason: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    timestamp: float = field(default_factory=time.time)
    resolved_at: float | None = None
    approved_by: str = ""


class ApprovalManager:
    """Manages approval requests for response actions.

    Actions that require approval are queued. They can be approved or denied
    via approve() / deny(). If the policy allows auto-respond, certain actions
    are auto-approved.
    """

    def __init__(self, policy: ResponsePolicy) -> None:
        self.policy = policy
        self._pending: dict[str, ApprovalRequest] = {}
        self._history: list[ApprovalRequest] = []
        self._next_id = 1

    def request_approval(
        self,
        action: ResponseAction,
        target_pid: int | None = None,
        target_path: str | None = None,
        severity: str = "",
        reason: str = "",
    ) -> ApprovalRequest:
        """Create an approval request for a response action.

        If the policy does not require approval, auto-approves immediately.
        """
        request_id = f"approval-{self._next_id}"
        self._next_id += 1

        request = ApprovalRequest(
            request_id=request_id,
            action=action,
            target_pid=target_pid,
            target_path=target_path,
            severity=severity,
            reason=reason,
        )

        if not self.policy.requires_approval(action):
            request.status = ApprovalStatus.AUTO_APPROVED
            request.resolved_at = time.time()
            request.approved_by = "policy:auto_respond"
            self._history.append(request)
            logger.info(
                "Auto-approved %s for PID=%s path=%s",
                action.value,
                target_pid,
                target_path,
            )
            return request

        self._pending[request_id] = request
        logger.info(
            "Approval required for %s (PID=%s, path=%s) — request %s",
            action.value,
            target_pid,
            target_path,
            request_id,
        )
        return request

    def approve(self, request_id: str, approved_by: str = "operator") -> ApprovalRequest | None:
        """Approve a pending request."""
        request = self._pending.pop(request_id, None)
        if request is None:
            return None

        request.status = ApprovalStatus.APPROVED
        request.resolved_at = time.time()
        request.approved_by = approved_by
        self._history.append(request)
        logger.info("Approved %s by %s", request_id, approved_by)
        return request

    def deny(self, request_id: str, denied_by: str = "operator") -> ApprovalRequest | None:
        """Deny a pending request."""
        request = self._pending.pop(request_id, None)
        if request is None:
            return None

        request.status = ApprovalStatus.DENIED
        request.resolved_at = time.time()
        request.approved_by = denied_by
        self._history.append(request)
        logger.info("Denied %s by %s", request_id, denied_by)
        return request

    @property
    def pending_requests(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending.values())

    @property
    def history(self) -> list[ApprovalRequest]:
        """Get all resolved approval requests."""
        return list(self._history)

    def is_approved(self, request_id: str) -> bool:
        """Check if a request has been approved (manually or auto)."""
        for req in self._history:
            if req.request_id == request_id:
                return req.status in (ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED)
        return False
