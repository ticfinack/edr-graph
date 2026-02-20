"""Tests for Phase 3 Commit 2: Process Control (3B)."""

import os
import signal
import subprocess
import sys

from agent.response.process_control import (
    ProcessControlOutcome,
    ProcessControlResult,
    resume_process,
    suspend_process,
    terminate_process,
)


class TestSuspendProcess:
    def test_suspend_running_process(self):
        """Suspending a running child process succeeds."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )
        try:
            outcome = suspend_process(proc.pid)
            assert outcome.result == ProcessControlResult.SUCCESS
            assert outcome.pid == proc.pid
            assert outcome.action == "suspend"
        finally:
            proc.kill()
            proc.wait()

    def test_suspend_nonexistent_pid(self):
        """Suspending a non-existent PID returns NOT_FOUND."""
        outcome = suspend_process(99999999)
        assert outcome.result == ProcessControlResult.NOT_FOUND
        assert outcome.pid == 99999999
        assert outcome.action == "suspend"

    def test_suspend_preserves_process(self):
        """After suspension, the process still exists (not killed)."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )
        try:
            suspend_process(proc.pid)
            # Process should still be alive (stopped, not terminated)
            assert proc.poll() is None
        finally:
            # Resume before kill to avoid zombie
            os.kill(proc.pid, signal.SIGCONT)
            proc.kill()
            proc.wait()


class TestResumeProcess:
    def test_resume_suspended_process(self):
        """Resuming a suspended process succeeds."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )
        try:
            suspend_process(proc.pid)
            outcome = resume_process(proc.pid)
            assert outcome.result == ProcessControlResult.SUCCESS
            assert outcome.pid == proc.pid
            assert outcome.action == "resume"
        finally:
            proc.kill()
            proc.wait()

    def test_resume_nonexistent_pid(self):
        """Resuming a non-existent PID returns NOT_FOUND."""
        outcome = resume_process(99999999)
        assert outcome.result == ProcessControlResult.NOT_FOUND
        assert outcome.action == "resume"


class TestTerminateProcess:
    def test_terminate_running_process(self):
        """Terminating a running process succeeds and process exits."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
        )
        outcome = terminate_process(proc.pid)
        assert outcome.result == ProcessControlResult.SUCCESS
        assert outcome.pid == proc.pid
        assert outcome.action == "terminate"
        # Wait for process to actually die
        proc.wait(timeout=5)
        assert proc.poll() is not None

    def test_terminate_nonexistent_pid(self):
        """Terminating a non-existent PID returns NOT_FOUND."""
        outcome = terminate_process(99999999)
        assert outcome.result == ProcessControlResult.NOT_FOUND
        assert outcome.action == "terminate"


class TestProcessControlOutcome:
    def test_outcome_dataclass_fields(self):
        """ProcessControlOutcome has all expected fields."""
        outcome = ProcessControlOutcome(
            result=ProcessControlResult.SUCCESS,
            pid=1234,
            action="suspend",
            detail="test detail",
        )
        assert outcome.result == ProcessControlResult.SUCCESS
        assert outcome.pid == 1234
        assert outcome.action == "suspend"
        assert outcome.detail == "test detail"

    def test_outcome_default_detail(self):
        """ProcessControlOutcome detail defaults to empty string."""
        outcome = ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=0,
            action="terminate",
        )
        assert outcome.detail == ""


class TestProcessControlResultEnum:
    def test_all_result_values(self):
        """All expected result variants exist."""
        assert ProcessControlResult.SUCCESS.value == "success"
        assert ProcessControlResult.PROTECTED.value == "protected"
        assert ProcessControlResult.NOT_FOUND.value == "not_found"
        assert ProcessControlResult.PERMISSION_DENIED.value == "permission_denied"
        assert ProcessControlResult.FAILED.value == "failed"
