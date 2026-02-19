"""Response action definitions, severity-to-action policy, and protected process list."""

from __future__ import annotations

from enum import Enum


class ResponseAction(Enum):
    """Available response actions, ordered by severity."""

    LOG_ONLY = "log_only"
    ALERT = "alert"
    SUSPEND_PROCESS = "suspend_process"
    TERMINATE_PROCESS = "terminate_process"
    ISOLATE_NETWORK = "isolate_network"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_CONNECTION = "block_connection"
    DNS_SINKHOLE = "dns_sinkhole"
    PANIC_ISOLATE = "panic_isolate"


# Processes that must NEVER be suspended or terminated.
# Terminating these causes BSOD (Windows) or system instability (Linux/macOS).
PROTECTED_PROCESSES: set[str] = {
    # Windows critical processes
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "System",
    "Registry",
    "Memory Compression",
    # Linux critical processes
    "systemd",
    "init",
    "kthreadd",
    "ksoftirqd",
    "kworker",
    # macOS critical processes
    "launchd",
    "kernel_task",
    "WindowServer",
    # The agent itself
    "edr-graph",
    "edr-watchdog",
}


class ResponsePolicy:
    """Maps LLM severity verdicts to response actions.

    The policy determines which actions are taken for each severity level.
    Actions are returned in execution order.
    """

    SEVERITY_MAP: dict[str, list[ResponseAction]] = {
        "info": [ResponseAction.LOG_ONLY],
        "low": [ResponseAction.LOG_ONLY],
        "medium": [ResponseAction.ALERT],
        "high": [ResponseAction.ALERT, ResponseAction.BLOCK_CONNECTION],
        "critical": [
            ResponseAction.ALERT,
            ResponseAction.SUSPEND_PROCESS,
            ResponseAction.BLOCK_CONNECTION,
        ],
    }

    def __init__(
        self,
        auto_respond: bool = False,
        auto_terminate: bool = False,
        protected_processes: set[str] | None = None,
    ) -> None:
        self.auto_respond = auto_respond
        self.auto_terminate = auto_terminate
        self.protected_processes = protected_processes or PROTECTED_PROCESSES

    def get_actions(self, severity: str) -> list[ResponseAction]:
        """Get the list of response actions for a given severity level."""
        return self.SEVERITY_MAP.get(severity.lower(), [ResponseAction.LOG_ONLY])

    def is_protected(self, process_name: str) -> bool:
        """Check if a process is in the protected list."""
        return process_name.lower() in {p.lower() for p in self.protected_processes}

    def requires_approval(self, action: ResponseAction) -> bool:
        """Check if an action requires human approval before execution.

        Destructive actions (terminate, quarantine) always require approval
        unless auto_respond is enabled and the action is not termination,
        or auto_terminate is also enabled.
        """
        if action in (ResponseAction.LOG_ONLY, ResponseAction.ALERT):
            return False

        if action == ResponseAction.TERMINATE_PROCESS:
            return not (self.auto_respond and self.auto_terminate)

        # suspend, isolate, quarantine
        return not self.auto_respond
