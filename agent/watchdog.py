"""Lightweight watchdog process for mutual monitoring with the EDR agent.

The watchdog:
1. Monitors the main agent process via PID file and heartbeat file.
2. Restarts the agent if it dies or stops heartbeating.
3. Writes its own heartbeat so the agent can monitor it back.

Design principles:
- stdlib only — no third-party imports, hard to crash.
- Minimal attack surface — no network, no complex logic.
- Communication via heartbeat files (not shared memory).

Usage:
    python -m agent.watchdog --agent-pid-file /tmp/edr-agent.pid \
                             --heartbeat-dir /tmp/edr-heartbeats \
                             --agent-cmd "edr-graph --no-dashboard"

The agent should call write_heartbeat() periodically and monitor the
watchdog's heartbeat via check_watchdog_alive().
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path

# Default configuration
DEFAULT_HEARTBEAT_DIR = "/tmp/edr-heartbeats"
DEFAULT_HEARTBEAT_INTERVAL = 5  # seconds
DEFAULT_HEARTBEAT_TIMEOUT = 30  # seconds — agent is dead if no heartbeat for this long
DEFAULT_CHECK_INTERVAL = 5  # seconds

AGENT_HEARTBEAT_FILE = "agent.heartbeat"
WATCHDOG_HEARTBEAT_FILE = "watchdog.heartbeat"
AGENT_PID_FILE = "agent.pid"
WATCHDOG_PID_FILE = "watchdog.pid"


def write_heartbeat(heartbeat_dir: str | Path, name: str = AGENT_HEARTBEAT_FILE) -> None:
    """Write a heartbeat file with the current timestamp and PID.

    Called by the agent or watchdog to signal liveness.
    """
    heartbeat_dir = Path(heartbeat_dir)
    heartbeat_dir.mkdir(parents=True, exist_ok=True)
    heartbeat_path = heartbeat_dir / name
    data = {
        "pid": os.getpid(),
        "timestamp": time.time(),
    }
    # Atomic write: write to temp file then rename
    tmp_path = heartbeat_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data))
    tmp_path.rename(heartbeat_path)


def read_heartbeat(heartbeat_dir: str | Path, name: str) -> dict | None:
    """Read a heartbeat file. Returns None if missing or corrupt."""
    path = Path(heartbeat_dir) / name
    try:
        data = json.loads(path.read_text())
        return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)  # Signal 0 = check existence without killing
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Process exists but we can't signal it
    except OSError:
        return False


def write_pid_file(heartbeat_dir: str | Path, name: str = WATCHDOG_PID_FILE) -> None:
    """Write the current process PID to a file."""
    path = Path(heartbeat_dir) / name
    Path(heartbeat_dir).mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))


def read_pid_file(heartbeat_dir: str | Path, name: str) -> int | None:
    """Read a PID from a file. Returns None if missing or invalid."""
    path = Path(heartbeat_dir) / name
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def check_agent_alive(
    heartbeat_dir: str | Path,
    timeout: float = DEFAULT_HEARTBEAT_TIMEOUT,
) -> bool:
    """Check if the agent is alive based on heartbeat and PID.

    Returns True if:
    - The heartbeat file exists AND
    - The heartbeat timestamp is within the timeout AND
    - The PID in the heartbeat is a running process
    """
    hb = read_heartbeat(heartbeat_dir, AGENT_HEARTBEAT_FILE)
    if hb is None:
        return False

    # Check timestamp freshness
    age = time.time() - hb.get("timestamp", 0)
    if age > timeout:
        return False

    # Check PID is running
    pid = hb.get("pid", 0)
    return is_process_alive(pid)


def check_watchdog_alive(
    heartbeat_dir: str | Path,
    timeout: float = DEFAULT_HEARTBEAT_TIMEOUT,
) -> bool:
    """Check if the watchdog is alive (called by the agent for mutual monitoring)."""
    hb = read_heartbeat(heartbeat_dir, WATCHDOG_HEARTBEAT_FILE)
    if hb is None:
        return False

    age = time.time() - hb.get("timestamp", 0)
    if age > timeout:
        return False

    pid = hb.get("pid", 0)
    return is_process_alive(pid)


class Watchdog:
    """Main watchdog loop. Monitors the agent and restarts it if necessary."""

    def __init__(
        self,
        heartbeat_dir: str | Path,
        agent_cmd: list[str],
        heartbeat_interval: float = DEFAULT_HEARTBEAT_INTERVAL,
        heartbeat_timeout: float = DEFAULT_HEARTBEAT_TIMEOUT,
        check_interval: float = DEFAULT_CHECK_INTERVAL,
    ) -> None:
        self.heartbeat_dir = Path(heartbeat_dir)
        self.agent_cmd = agent_cmd
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_timeout = heartbeat_timeout
        self.check_interval = check_interval
        self._running = True
        self._agent_process: subprocess.Popen | None = None
        self._restart_count = 0

    def start(self) -> None:
        """Start the watchdog loop."""
        self.heartbeat_dir.mkdir(parents=True, exist_ok=True)
        write_pid_file(self.heartbeat_dir, WATCHDOG_PID_FILE)

        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self._log("Watchdog started (PID %d)", os.getpid())
        self._log("Monitoring agent command: %s", " ".join(self.agent_cmd))
        self._log("Heartbeat dir: %s", self.heartbeat_dir)

        # Start the agent if it's not already running
        if not check_agent_alive(self.heartbeat_dir, self.heartbeat_timeout):
            self._start_agent()

        # Main monitoring loop
        last_heartbeat = 0.0
        while self._running:
            now = time.time()

            # Write our own heartbeat
            if now - last_heartbeat >= self.heartbeat_interval:
                write_heartbeat(self.heartbeat_dir, WATCHDOG_HEARTBEAT_FILE)
                last_heartbeat = now

            # Check if agent is alive
            if not check_agent_alive(self.heartbeat_dir, self.heartbeat_timeout):
                self._log("Agent appears dead, restarting...")
                self._start_agent()

            # Also check subprocess directly if we started it
            if self._agent_process and self._agent_process.poll() is not None:
                exit_code = self._agent_process.returncode
                self._log("Agent process exited with code %d", exit_code)
                self._agent_process = None
                if self._running:
                    self._start_agent()

            time.sleep(self.check_interval)

        self._log("Watchdog stopping")
        self._stop_agent()
        self._cleanup()

    def _start_agent(self) -> None:
        """Start or restart the agent process."""
        self._stop_agent()
        self._restart_count += 1
        self._log(
            "Starting agent (attempt %d): %s",
            self._restart_count,
            " ".join(self.agent_cmd),
        )
        try:
            self._agent_process = subprocess.Popen(
                self.agent_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._log("Agent started with PID %d", self._agent_process.pid)
        except Exception as e:
            self._log("Failed to start agent: %s", e)

    def _stop_agent(self) -> None:
        """Stop the agent process if we started it."""
        if self._agent_process is None:
            return

        if self._agent_process.poll() is not None:
            self._agent_process = None
            return

        self._log("Sending SIGTERM to agent PID %d", self._agent_process.pid)
        try:
            self._agent_process.terminate()
            try:
                self._agent_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._log("Agent didn't stop gracefully, sending SIGKILL")
                self._agent_process.kill()
                self._agent_process.wait(timeout=5)
        except OSError:
            pass
        self._agent_process = None

    def _cleanup(self) -> None:
        """Clean up PID and heartbeat files."""
        for name in (WATCHDOG_PID_FILE, WATCHDOG_HEARTBEAT_FILE):
            path = self.heartbeat_dir / name
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    def _handle_signal(self, signum, frame):
        self._log("Received signal %d", signum)
        self._running = False

    @staticmethod
    def _log(msg: str, *args) -> None:
        """Simple logging — no external dependencies."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        formatted = msg % args if args else msg
        print(f"[{timestamp}] watchdog: {formatted}", flush=True)


def main() -> None:
    """CLI entry point for the watchdog."""
    import argparse

    parser = argparse.ArgumentParser(description="EDR Graph Agent Watchdog")
    parser.add_argument(
        "--heartbeat-dir",
        default=DEFAULT_HEARTBEAT_DIR,
        help=f"Directory for heartbeat files (default: {DEFAULT_HEARTBEAT_DIR})",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=DEFAULT_HEARTBEAT_INTERVAL,
        help=f"Heartbeat write interval in seconds (default: {DEFAULT_HEARTBEAT_INTERVAL})",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=DEFAULT_HEARTBEAT_TIMEOUT,
        help=f"Heartbeat timeout in seconds (default: {DEFAULT_HEARTBEAT_TIMEOUT})",
    )
    parser.add_argument(
        "--check-interval",
        type=float,
        default=DEFAULT_CHECK_INTERVAL,
        help=f"Check interval in seconds (default: {DEFAULT_CHECK_INTERVAL})",
    )
    parser.add_argument(
        "--agent-cmd",
        default="edr-graph --no-dashboard",
        help="Command to start the agent (default: 'edr-graph --no-dashboard')",
    )
    args = parser.parse_args()

    watchdog = Watchdog(
        heartbeat_dir=args.heartbeat_dir,
        agent_cmd=args.agent_cmd.split(),
        heartbeat_interval=args.heartbeat_interval,
        heartbeat_timeout=args.heartbeat_timeout,
        check_interval=args.check_interval,
    )
    watchdog.start()


if __name__ == "__main__":
    main()
