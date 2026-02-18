"""Process suspension and termination for response actions.

Windows: NtSuspendProcess/NtResumeProcess via ctypes (preserves forensic state).
Linux/macOS: SIGSTOP/SIGCONT for suspension, SIGKILL for termination.

Protected processes are never targeted — callers must check is_protected() first.
"""

from __future__ import annotations

import logging
import os
import signal
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ProcessControlResult(Enum):
    """Outcome of a process control operation."""

    SUCCESS = "success"
    PROTECTED = "protected"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    FAILED = "failed"


@dataclass
class ProcessControlOutcome:
    """Result of a process control action with context."""

    result: ProcessControlResult
    pid: int
    action: str  # "suspend", "resume", "terminate"
    detail: str = ""


def suspend_process(pid: int) -> ProcessControlOutcome:
    """Suspend a process, preserving its state for forensic analysis.

    Windows: NtSuspendProcess via ctypes.
    Linux/macOS: SIGSTOP signal.
    """
    if os.name == "nt":
        return _suspend_windows(pid)
    return _suspend_unix(pid)


def resume_process(pid: int) -> ProcessControlOutcome:
    """Resume a previously suspended process.

    Windows: NtResumeProcess via ctypes.
    Linux/macOS: SIGCONT signal.
    """
    if os.name == "nt":
        return _resume_windows(pid)
    return _resume_unix(pid)


def terminate_process(pid: int) -> ProcessControlOutcome:
    """Terminate a process. This is irreversible.

    Windows: TerminateProcess via ctypes.
    Linux/macOS: SIGKILL signal.
    """
    if os.name == "nt":
        return _terminate_windows(pid)
    return _terminate_unix(pid)


# --- Unix implementations ---


def _suspend_unix(pid: int) -> ProcessControlOutcome:
    """Send SIGSTOP to suspend a process on Unix."""
    try:
        os.kill(pid, signal.SIGSTOP)
        logger.info("Suspended process %d via SIGSTOP", pid)
        return ProcessControlOutcome(
            result=ProcessControlResult.SUCCESS,
            pid=pid,
            action="suspend",
            detail="SIGSTOP sent",
        )
    except ProcessLookupError:
        return ProcessControlOutcome(
            result=ProcessControlResult.NOT_FOUND,
            pid=pid,
            action="suspend",
            detail=f"PID {pid} does not exist",
        )
    except PermissionError:
        return ProcessControlOutcome(
            result=ProcessControlResult.PERMISSION_DENIED,
            pid=pid,
            action="suspend",
            detail=f"Insufficient permissions to suspend PID {pid}",
        )
    except OSError as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="suspend",
            detail=str(e),
        )


def _resume_unix(pid: int) -> ProcessControlOutcome:
    """Send SIGCONT to resume a process on Unix."""
    try:
        os.kill(pid, signal.SIGCONT)
        logger.info("Resumed process %d via SIGCONT", pid)
        return ProcessControlOutcome(
            result=ProcessControlResult.SUCCESS,
            pid=pid,
            action="resume",
            detail="SIGCONT sent",
        )
    except ProcessLookupError:
        return ProcessControlOutcome(
            result=ProcessControlResult.NOT_FOUND,
            pid=pid,
            action="resume",
            detail=f"PID {pid} does not exist",
        )
    except PermissionError:
        return ProcessControlOutcome(
            result=ProcessControlResult.PERMISSION_DENIED,
            pid=pid,
            action="resume",
            detail=f"Insufficient permissions to resume PID {pid}",
        )
    except OSError as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="resume",
            detail=str(e),
        )


def _terminate_unix(pid: int) -> ProcessControlOutcome:
    """Send SIGKILL to terminate a process on Unix."""
    try:
        os.kill(pid, signal.SIGKILL)
        logger.info("Terminated process %d via SIGKILL", pid)
        return ProcessControlOutcome(
            result=ProcessControlResult.SUCCESS,
            pid=pid,
            action="terminate",
            detail="SIGKILL sent",
        )
    except ProcessLookupError:
        return ProcessControlOutcome(
            result=ProcessControlResult.NOT_FOUND,
            pid=pid,
            action="terminate",
            detail=f"PID {pid} does not exist",
        )
    except PermissionError:
        return ProcessControlOutcome(
            result=ProcessControlResult.PERMISSION_DENIED,
            pid=pid,
            action="terminate",
            detail=f"Insufficient permissions to terminate PID {pid}",
        )
    except OSError as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="terminate",
            detail=str(e),
        )


# --- Windows implementations ---


def _suspend_windows(pid: int) -> ProcessControlOutcome:
    """Use NtSuspendProcess to freeze a process on Windows."""
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_SUSPEND_RESUME = 0x0800
        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # ERROR_INVALID_PARAMETER
                return ProcessControlOutcome(
                    result=ProcessControlResult.NOT_FOUND,
                    pid=pid,
                    action="suspend",
                    detail=f"PID {pid} does not exist",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.PERMISSION_DENIED,
                pid=pid,
                action="suspend",
                detail=f"OpenProcess failed with error {error}",
            )

        try:
            status = ntdll.NtSuspendProcess(handle)
            if status == 0:
                logger.info("Suspended process %d via NtSuspendProcess", pid)
                return ProcessControlOutcome(
                    result=ProcessControlResult.SUCCESS,
                    pid=pid,
                    action="suspend",
                    detail="NtSuspendProcess succeeded",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.FAILED,
                pid=pid,
                action="suspend",
                detail=f"NtSuspendProcess returned NTSTATUS 0x{status:08X}",
            )
        finally:
            kernel32.CloseHandle(handle)
    except Exception as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="suspend",
            detail=str(e),
        )


def _resume_windows(pid: int) -> ProcessControlOutcome:
    """Use NtResumeProcess to resume a process on Windows."""
    try:
        import ctypes

        PROCESS_SUSPEND_RESUME = 0x0800
        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return ProcessControlOutcome(
                    result=ProcessControlResult.NOT_FOUND,
                    pid=pid,
                    action="resume",
                    detail=f"PID {pid} does not exist",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.PERMISSION_DENIED,
                pid=pid,
                action="resume",
                detail=f"OpenProcess failed with error {error}",
            )

        try:
            status = ntdll.NtResumeProcess(handle)
            if status == 0:
                logger.info("Resumed process %d via NtResumeProcess", pid)
                return ProcessControlOutcome(
                    result=ProcessControlResult.SUCCESS,
                    pid=pid,
                    action="resume",
                    detail="NtResumeProcess succeeded",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.FAILED,
                pid=pid,
                action="resume",
                detail=f"NtResumeProcess returned NTSTATUS 0x{status:08X}",
            )
        finally:
            kernel32.CloseHandle(handle)
    except Exception as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="resume",
            detail=str(e),
        )


def _terminate_windows(pid: int) -> ProcessControlOutcome:
    """Use TerminateProcess to kill a process on Windows."""
    try:
        import ctypes

        PROCESS_TERMINATE = 0x0001
        kernel32 = ctypes.windll.kernel32

        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return ProcessControlOutcome(
                    result=ProcessControlResult.NOT_FOUND,
                    pid=pid,
                    action="terminate",
                    detail=f"PID {pid} does not exist",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.PERMISSION_DENIED,
                pid=pid,
                action="terminate",
                detail=f"OpenProcess failed with error {error}",
            )

        try:
            success = kernel32.TerminateProcess(handle, 1)
            if success:
                logger.info("Terminated process %d via TerminateProcess", pid)
                return ProcessControlOutcome(
                    result=ProcessControlResult.SUCCESS,
                    pid=pid,
                    action="terminate",
                    detail="TerminateProcess succeeded",
                )
            return ProcessControlOutcome(
                result=ProcessControlResult.FAILED,
                pid=pid,
                action="terminate",
                detail=f"TerminateProcess failed with error {ctypes.get_last_error()}",
            )
        finally:
            kernel32.CloseHandle(handle)
    except Exception as e:
        return ProcessControlOutcome(
            result=ProcessControlResult.FAILED,
            pid=pid,
            action="terminate",
            detail=str(e),
        )
