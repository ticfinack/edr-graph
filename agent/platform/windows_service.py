"""Windows Service wrapper for the EDR agent.

Implements a Windows Service using pywin32 so the agent runs as SYSTEM,
starts automatically, and restarts on failure.

Usage:
    # Install the service
    python -m agent.platform.windows_service install

    # Start/stop
    python -m agent.platform.windows_service start
    python -m agent.platform.windows_service stop

    # Remove
    python -m agent.platform.windows_service remove

Requires: pywin32 (only available on Windows)
"""

from __future__ import annotations

import contextlib
import logging
import sys

logger = logging.getLogger(__name__)

SERVICE_NAME = "EDRGraphAgent"
SERVICE_DISPLAY_NAME = "EDR Graph Agent"
SERVICE_DESCRIPTION = (
    "Local EDR with Graph-Based Event Correlation & AI Analysis. "
    "Monitors system activity, detects threats, and executes response actions."
)

# Recovery: restart on first, second, and subsequent failures (1s delay)
RECOVERY_ACTIONS = [
    (1, 1000),  # First failure: restart after 1 second
    (1, 1000),  # Second failure: restart after 1 second
    (1, 1000),  # Subsequent failures: restart after 1 second
]


def _check_pywin32() -> bool:
    """Check if pywin32 is available."""
    try:
        import win32serviceutil  # noqa: F401

        return True
    except ImportError:
        return False


def _get_service_class():
    """Dynamically build the service class (only on Windows with pywin32)."""
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class EDRGraphService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._agent_thread = None

        def SvcStop(self):
            """Handle service stop request."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logger.info("Service stop requested")
            win32event.SetEvent(self._stop_event)

            # Signal the agent to shut down
            from agent.main import _shutdown

            _shutdown.set()

        def SvcDoRun(self):
            """Main service entry point."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            logger.info("Service starting")

            try:
                self._run_agent()
            except Exception:
                logger.exception("Service failed")
            finally:
                logger.info("Service stopped")

        def _run_agent(self):
            """Run the agent main loop."""
            import threading

            from agent.main import _shutdown, main

            # Run main() in a thread so we can wait for the stop event
            def agent_main():
                sys.argv = [sys.argv[0], "--no-dashboard", "--log-format", "json"]
                with contextlib.suppress(SystemExit):
                    main()

            self._agent_thread = threading.Thread(target=agent_main, daemon=True, name="agent-main")
            self._agent_thread.start()

            # Wait for stop signal
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

            # Ensure agent shuts down
            _shutdown.set()
            if self._agent_thread:
                self._agent_thread.join(timeout=10)

    return EDRGraphService


def configure_recovery(service_name: str = SERVICE_NAME) -> None:
    """Configure service recovery options (restart on failure).

    Sets the service to restart after 1 second on first, second, and
    subsequent failures.
    """
    try:
        import win32service

        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        try:
            hs = win32service.OpenService(hscm, service_name, win32service.SERVICE_ALL_ACCESS)
            try:
                # SC_ACTION_RESTART = 1
                actions = [(1, delay_ms) for _, delay_ms in RECOVERY_ACTIONS]
                # Reset failure count after 86400 seconds (1 day)
                win32service.ChangeServiceConfig2(
                    hs,
                    win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                    {
                        "ResetPeriod": 86400,
                        "RebootMsg": "",
                        "Command": "",
                        "Actions": actions,
                    },
                )
                logger.info("Recovery options configured for %s", service_name)
            finally:
                win32service.CloseServiceHandle(hs)
        finally:
            win32service.CloseServiceHandle(hscm)
    except Exception:
        logger.exception("Failed to configure recovery options")


def install_service() -> bool:
    """Install and configure the Windows service."""
    if not _check_pywin32():
        logger.error("pywin32 is required for Windows service support")
        return False

    try:
        import win32serviceutil

        svc_class = _get_service_class()
        win32serviceutil.InstallService(
            svc_class._svc_reg_class_,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            startType=2,  # SERVICE_AUTO_START
            description=SERVICE_DESCRIPTION,
        )
        configure_recovery()
        logger.info("Service '%s' installed successfully", SERVICE_NAME)
        return True
    except Exception:
        logger.exception("Failed to install service")
        return False


def remove_service() -> bool:
    """Remove the Windows service."""
    if not _check_pywin32():
        return False

    try:
        import win32serviceutil

        win32serviceutil.RemoveService(SERVICE_NAME)
        logger.info("Service '%s' removed", SERVICE_NAME)
        return True
    except Exception:
        logger.exception("Failed to remove service")
        return False


def main():
    """Entry point for service management commands."""
    if not _check_pywin32():
        print("Error: pywin32 is required. Install with: pip install pywin32")
        sys.exit(1)

    import servicemanager
    import win32serviceutil

    svc_class = _get_service_class()

    if len(sys.argv) == 1:
        # Started by SCM — run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(svc_class)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # CLI management: install, start, stop, remove, etc.
        win32serviceutil.HandleCommandLine(svc_class)


if __name__ == "__main__":
    main()
