"""Tests for Phase 3 Commit 1: Response Action Framework (3A)."""

from agent.response.actions import (
    PROTECTED_PROCESSES,
    ResponseAction,
    ResponsePolicy,
)


class TestResponsePolicy:
    def test_info_returns_log_only(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("info")
        assert actions == [ResponseAction.LOG_ONLY]

    def test_low_returns_log_only(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("low")
        assert actions == [ResponseAction.LOG_ONLY]

    def test_medium_returns_alert(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("medium")
        assert actions == [ResponseAction.ALERT]

    def test_high_returns_alert_and_block_connection(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("high")
        assert ResponseAction.ALERT in actions
        assert ResponseAction.BLOCK_CONNECTION in actions

    def test_critical_returns_alert_suspend_block_connection(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("critical")
        assert ResponseAction.ALERT in actions
        assert ResponseAction.SUSPEND_PROCESS in actions
        assert ResponseAction.BLOCK_CONNECTION in actions

    def test_unknown_severity_defaults_to_log_only(self):
        policy = ResponsePolicy()
        actions = policy.get_actions("banana")
        assert actions == [ResponseAction.LOG_ONLY]

    def test_case_insensitive_severity(self):
        policy = ResponsePolicy()
        assert policy.get_actions("HIGH") == policy.get_actions("high")
        assert policy.get_actions("Critical") == policy.get_actions("critical")


class TestProtectedProcesses:
    def test_windows_critical_processes_protected(self):
        policy = ResponsePolicy()
        for proc in ["csrss.exe", "lsass.exe", "svchost.exe", "System"]:
            assert policy.is_protected(proc), f"{proc} should be protected"

    def test_linux_critical_processes_protected(self):
        policy = ResponsePolicy()
        for proc in ["systemd", "init", "kthreadd"]:
            assert policy.is_protected(proc), f"{proc} should be protected"

    def test_agent_is_protected(self):
        policy = ResponsePolicy()
        assert policy.is_protected("edr-graph")
        assert policy.is_protected("edr-watchdog")

    def test_case_insensitive_protection(self):
        policy = ResponsePolicy()
        assert policy.is_protected("CSRSS.EXE")
        assert policy.is_protected("Systemd")

    def test_regular_process_not_protected(self):
        policy = ResponsePolicy()
        assert not policy.is_protected("malware.exe")
        assert not policy.is_protected("python")
        assert not policy.is_protected("curl")

    def test_custom_protected_list(self):
        policy = ResponsePolicy(protected_processes={"myapp.exe", "custom_daemon"})
        assert policy.is_protected("myapp.exe")
        assert not policy.is_protected("csrss.exe")  # not in custom list


class TestApprovalRequirements:
    def test_log_only_no_approval(self):
        policy = ResponsePolicy()
        assert not policy.requires_approval(ResponseAction.LOG_ONLY)

    def test_alert_no_approval(self):
        policy = ResponsePolicy()
        assert not policy.requires_approval(ResponseAction.ALERT)

    def test_suspend_requires_approval_by_default(self):
        policy = ResponsePolicy()
        assert policy.requires_approval(ResponseAction.SUSPEND_PROCESS)

    def test_terminate_requires_approval_by_default(self):
        policy = ResponsePolicy()
        assert policy.requires_approval(ResponseAction.TERMINATE_PROCESS)

    def test_isolate_requires_approval_by_default(self):
        policy = ResponsePolicy()
        assert policy.requires_approval(ResponseAction.ISOLATE_NETWORK)

    def test_auto_respond_skips_approval_for_suspend(self):
        policy = ResponsePolicy(auto_respond=True)
        assert not policy.requires_approval(ResponseAction.SUSPEND_PROCESS)
        assert not policy.requires_approval(ResponseAction.ISOLATE_NETWORK)
        # Terminate still requires auto_terminate
        assert policy.requires_approval(ResponseAction.TERMINATE_PROCESS)

    def test_auto_terminate_allows_termination(self):
        policy = ResponsePolicy(auto_respond=True, auto_terminate=True)
        assert not policy.requires_approval(ResponseAction.TERMINATE_PROCESS)

    def test_auto_terminate_without_auto_respond(self):
        """auto_terminate alone is not enough — need auto_respond too."""
        policy = ResponsePolicy(auto_respond=False, auto_terminate=True)
        assert policy.requires_approval(ResponseAction.TERMINATE_PROCESS)
