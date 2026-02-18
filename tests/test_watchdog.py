"""Tests for Phase 4 Commit 3: Watchdog Process (4C)."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent.watchdog import (
    AGENT_HEARTBEAT_FILE,
    WATCHDOG_HEARTBEAT_FILE,
    WATCHDOG_PID_FILE,
    Watchdog,
    check_agent_alive,
    check_watchdog_alive,
    is_process_alive,
    read_heartbeat,
    read_pid_file,
    write_heartbeat,
    write_pid_file,
)


class TestWriteHeartbeat:
    def test_creates_heartbeat_file(self, tmp_path):
        write_heartbeat(tmp_path, AGENT_HEARTBEAT_FILE)
        assert (tmp_path / AGENT_HEARTBEAT_FILE).exists()

    def test_heartbeat_contains_pid_and_timestamp(self, tmp_path):
        write_heartbeat(tmp_path, AGENT_HEARTBEAT_FILE)
        data = json.loads((tmp_path / AGENT_HEARTBEAT_FILE).read_text())
        assert data["pid"] == os.getpid()
        assert abs(data["timestamp"] - time.time()) < 2

    def test_creates_directory_if_missing(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        write_heartbeat(nested, AGENT_HEARTBEAT_FILE)
        assert (nested / AGENT_HEARTBEAT_FILE).exists()

    def test_overwrites_previous_heartbeat(self, tmp_path):
        write_heartbeat(tmp_path, AGENT_HEARTBEAT_FILE)
        time.sleep(0.01)
        write_heartbeat(tmp_path, AGENT_HEARTBEAT_FILE)
        data = json.loads((tmp_path / AGENT_HEARTBEAT_FILE).read_text())
        assert data["pid"] == os.getpid()


class TestReadHeartbeat:
    def test_reads_valid_heartbeat(self, tmp_path):
        write_heartbeat(tmp_path, "test.hb")
        data = read_heartbeat(tmp_path, "test.hb")
        assert data is not None
        assert data["pid"] == os.getpid()

    def test_returns_none_for_missing_file(self, tmp_path):
        assert read_heartbeat(tmp_path, "nonexistent.hb") is None

    def test_returns_none_for_corrupt_file(self, tmp_path):
        (tmp_path / "bad.hb").write_text("not json!")
        assert read_heartbeat(tmp_path, "bad.hb") is None


class TestIsProcessAlive:
    def test_current_process_is_alive(self):
        assert is_process_alive(os.getpid())

    def test_nonexistent_pid_is_not_alive(self):
        assert not is_process_alive(99999999)

    def test_zero_pid_is_not_alive(self):
        assert not is_process_alive(0)

    def test_negative_pid_is_not_alive(self):
        assert not is_process_alive(-1)


class TestPidFile:
    def test_write_and_read_pid(self, tmp_path):
        write_pid_file(tmp_path, "test.pid")
        pid = read_pid_file(tmp_path, "test.pid")
        assert pid == os.getpid()

    def test_read_missing_pid_file(self, tmp_path):
        assert read_pid_file(tmp_path, "nonexistent.pid") is None

    def test_read_invalid_pid_file(self, tmp_path):
        (tmp_path / "bad.pid").write_text("not a number")
        assert read_pid_file(tmp_path, "bad.pid") is None


class TestCheckAgentAlive:
    def test_alive_with_fresh_heartbeat(self, tmp_path):
        write_heartbeat(tmp_path, AGENT_HEARTBEAT_FILE)
        assert check_agent_alive(tmp_path, timeout=30)

    def test_dead_with_no_heartbeat(self, tmp_path):
        assert not check_agent_alive(tmp_path, timeout=30)

    def test_dead_with_stale_heartbeat(self, tmp_path):
        # Write heartbeat with old timestamp
        data = {"pid": os.getpid(), "timestamp": time.time() - 120}
        (tmp_path / AGENT_HEARTBEAT_FILE).write_text(json.dumps(data))
        assert not check_agent_alive(tmp_path, timeout=30)

    def test_dead_with_nonexistent_pid(self, tmp_path):
        data = {"pid": 99999999, "timestamp": time.time()}
        (tmp_path / AGENT_HEARTBEAT_FILE).write_text(json.dumps(data))
        assert not check_agent_alive(tmp_path, timeout=30)


class TestCheckWatchdogAlive:
    def test_alive_with_fresh_heartbeat(self, tmp_path):
        write_heartbeat(tmp_path, WATCHDOG_HEARTBEAT_FILE)
        assert check_watchdog_alive(tmp_path, timeout=30)

    def test_dead_with_no_heartbeat(self, tmp_path):
        assert not check_watchdog_alive(tmp_path, timeout=30)


class TestWatchdog:
    def test_watchdog_creates_pid_file(self, tmp_path):
        """Watchdog writes its PID file on start (tested via write_pid_file)."""
        write_pid_file(tmp_path, WATCHDOG_PID_FILE)
        pid = read_pid_file(tmp_path, WATCHDOG_PID_FILE)
        assert pid == os.getpid()

    def test_watchdog_init(self, tmp_path):
        wd = Watchdog(
            heartbeat_dir=tmp_path,
            agent_cmd=["echo", "hello"],
            heartbeat_interval=1,
            heartbeat_timeout=5,
            check_interval=1,
        )
        assert wd.heartbeat_dir == tmp_path
        assert wd.agent_cmd == ["echo", "hello"]
        assert wd._restart_count == 0

    def test_watchdog_restart_counter(self, tmp_path):
        """Calling _start_agent increments the restart counter."""
        wd = Watchdog(
            heartbeat_dir=tmp_path,
            agent_cmd=[sys.executable, "-c", "import time; time.sleep(60)"],
            heartbeat_interval=1,
            heartbeat_timeout=5,
            check_interval=1,
        )
        assert wd._restart_count == 0
        wd._start_agent()
        assert wd._restart_count == 1
        assert wd._agent_process is not None
        wd._stop_agent()
        wd._start_agent()
        assert wd._restart_count == 2
        wd._stop_agent()

    def test_watchdog_stop_agent(self, tmp_path):
        """_stop_agent terminates the managed process."""
        wd = Watchdog(
            heartbeat_dir=tmp_path,
            agent_cmd=[sys.executable, "-c", "import time; time.sleep(60)"],
        )
        wd._start_agent()
        pid = wd._agent_process.pid
        assert is_process_alive(pid)
        wd._stop_agent()
        assert wd._agent_process is None
        # Give OS a moment to clean up
        time.sleep(0.1)
        assert not is_process_alive(pid)
