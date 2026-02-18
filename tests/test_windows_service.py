"""Tests for Phase 4 Commit 1: Windows Service (4A).

Since pywin32 is not available on non-Windows platforms, we test the
module-level constants and guard logic.
"""

import sys

from agent.platform.windows_service import (
    RECOVERY_ACTIONS,
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    _check_pywin32,
)


class TestServiceConstants:
    def test_service_name(self):
        assert SERVICE_NAME == "EDRGraphAgent"

    def test_display_name(self):
        assert SERVICE_DISPLAY_NAME == "EDR Graph Agent"

    def test_description_not_empty(self):
        assert len(SERVICE_DESCRIPTION) > 20

    def test_recovery_actions_have_three_entries(self):
        assert len(RECOVERY_ACTIONS) == 3

    def test_recovery_actions_restart_after_1_second(self):
        for action_type, delay_ms in RECOVERY_ACTIONS:
            assert action_type == 1  # Restart
            assert delay_ms == 1000  # 1 second


class TestPywin32Guard:
    def test_check_pywin32_on_non_windows(self):
        """On macOS/Linux, pywin32 is not available."""
        if sys.platform != "win32":
            assert not _check_pywin32()
