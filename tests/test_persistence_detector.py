"""Tests for Phase 2 Commit 4: Persistence Detection (2C).

Tests rule-based persistence detection for registry and filesystem paths.
"""

import os
from datetime import datetime

from agent.analysis.persistence_detector import (
    check_persistence,
    check_persistence_for_path,
    check_persistence_for_registry,
)
from agent.processor.entity_extractor import extract_entities
from agent.schema.ocsf_types import (
    DeviceInfo,
    FileActivity,
    ProcessInfo,
    RegistryActivity,
)


class TestWindowsRegistryPersistence:
    def test_run_key_detection(self):
        """Writing to HKLM\\...\\Run\\malware triggers detection with correct ATT&CK ID."""
        event = RegistryActivity(
            activity_id=1,  # Create
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=1234, name="malware.exe", created_time=datetime(2025, 6, 1, 12, 0)),
            reg_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyMalware",
            reg_value_name="MyMalware",
            reg_value_data=r"C:\malware.exe",
            device=DeviceInfo(hostname="testhost"),
        )
        result = check_persistence(event)

        assert result is not None
        assert result.persistence_type == "registry_run_key"
        assert result.mitre_technique == "T1547.001"
        assert result.severity == "HIGH"
        assert result.platform == "windows"

    def test_prefix_matching(self):
        """HKLM\\...\\Run\\anything matches the Run key pattern."""
        result = check_persistence_for_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SomeProgram",
            process_name="test.exe",
        )
        assert result is not None
        assert result.persistence_type == "registry_run_key"

    def test_service_creation_detection(self):
        """Writing to Services registry triggers detection."""
        result = check_persistence_for_registry(
            r"HKLM\SYSTEM\CurrentControlSet\Services\EvilService",
        )
        assert result is not None
        assert result.persistence_type == "windows_service"
        assert result.mitre_technique == "T1543.003"

    def test_scheduled_task_detection(self):
        """Writing to TaskCache triggers detection."""
        result = check_persistence_for_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BadTask",
        )
        assert result is not None
        assert result.persistence_type == "scheduled_task"
        assert result.mitre_technique == "T1053.005"

    def test_appinit_dlls_detection(self):
        """Writing to AppInit_DLLs triggers detection."""
        result = check_persistence_for_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        )
        assert result is not None
        assert result.persistence_type == "appinit_dlls"
        assert result.mitre_technique == "T1546.010"

    def test_ifeo_detection(self):
        """Writing to IFEO triggers detection."""
        result = check_persistence_for_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe",
        )
        assert result is not None
        assert result.persistence_type == "ifeo_debugger"
        assert result.mitre_technique == "T1546.012"

    def test_case_insensitive_matching(self):
        """Registry path matching is case-insensitive."""
        result = check_persistence_for_registry(
            r"hklm\software\microsoft\windows\currentversion\run\test",
        )
        assert result is not None
        assert result.persistence_type == "registry_run_key"


class TestLinuxPersistence:
    def test_cron_detection(self):
        """Writing to /etc/cron.d/backdoor triggers detection on Linux."""
        result = check_persistence_for_path(
            "/etc/cron.d/backdoor",
            process_name="evil",
            platform="linux",
        )
        assert result is not None
        assert result.persistence_type == "cron_job"
        assert result.mitre_technique == "T1053.003"
        assert result.platform == "linux"

    def test_systemd_unit_detection(self):
        """Writing to /etc/systemd/system/ triggers detection."""
        result = check_persistence_for_path(
            "/etc/systemd/system/evil.service",
            platform="linux",
        )
        assert result is not None
        assert result.persistence_type == "systemd_unit"
        assert result.mitre_technique == "T1543.002"

    def test_ld_so_preload_detection(self):
        """Writing to /etc/ld.so.preload triggers detection."""
        result = check_persistence_for_path(
            "/etc/ld.so.preload",
            platform="linux",
        )
        assert result is not None
        assert result.persistence_type == "ld_preload"
        assert result.mitre_technique == "T1574.006"

    def test_bashrc_detection(self):
        """Writing to ~/.bashrc triggers shell profile detection."""
        home = os.path.expanduser("~")
        result = check_persistence_for_path(
            f"{home}/.bashrc",
            platform="linux",
        )
        assert result is not None
        assert result.persistence_type == "shell_profile"
        assert result.mitre_technique == "T1546.004"

    def test_init_d_detection(self):
        """Writing to /etc/init.d/ triggers detection."""
        result = check_persistence_for_path(
            "/etc/init.d/evil_daemon",
            platform="linux",
        )
        assert result is not None
        assert result.persistence_type == "init_script"


class TestMacOSPersistence:
    def test_launch_agent_detection(self):
        """Writing to ~/Library/LaunchAgents/evil.plist triggers detection on macOS."""
        home = os.path.expanduser("~")
        result = check_persistence_for_path(
            f"{home}/Library/LaunchAgents/evil.plist",
            process_name="installer",
            platform="macos",
        )
        assert result is not None
        assert result.persistence_type == "launch_agent"
        assert result.mitre_technique == "T1543.001"
        assert result.platform == "macos"

    def test_launch_daemon_detection(self):
        """Writing to /Library/LaunchDaemons/ triggers detection."""
        result = check_persistence_for_path(
            "/Library/LaunchDaemons/com.evil.daemon.plist",
            platform="macos",
        )
        assert result is not None
        assert result.persistence_type == "launch_daemon"
        assert result.mitre_technique == "T1543.004"

    def test_system_launch_agent_detection(self):
        """Writing to /Library/LaunchAgents/ triggers detection."""
        result = check_persistence_for_path(
            "/Library/LaunchAgents/com.evil.agent.plist",
            platform="macos",
        )
        assert result is not None
        assert result.persistence_type == "launch_agent"


class TestNonPersistencePaths:
    def test_non_persistence_path_returns_none(self):
        """Writing to /tmp/notes.txt returns None."""
        event = FileActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=100, name="touch", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/tmp/notes.txt",
            device=DeviceInfo(hostname="testhost"),
        )
        result = check_persistence(event)
        assert result is None

    def test_non_persistence_registry_returns_none(self):
        """Writing to a non-persistence registry path returns None."""
        result = check_persistence_for_registry(
            r"HKCU\SOFTWARE\MyApp\Settings\Theme",
        )
        assert result is None

    def test_file_read_event_not_checked(self):
        """Read events (activity_id=2) are not checked for persistence."""
        event = FileActivity(
            activity_id=2,  # Read
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=100, name="cat", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/etc/cron.d/important",
            device=DeviceInfo(hostname="testhost"),
        )
        result = check_persistence(event)
        assert result is None

    def test_registry_delete_not_checked(self):
        """Registry delete events (activity_id=4) are not checked."""
        event = RegistryActivity(
            activity_id=4,  # Delete
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=100, name="reg.exe", created_time=datetime(2025, 6, 1, 12, 0)),
            reg_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OldEntry",
            device=DeviceInfo(hostname="testhost"),
        )
        result = check_persistence(event)
        assert result is None


class TestPersistenceInAttackChain:
    def test_persistence_in_risk_indicators(self):
        """Persistence results appear in entity extraction risk_indicators."""
        event = RegistryActivity(
            activity_id=1,  # Create
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=9999,
                name="malware.exe",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            reg_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil",
            reg_value_name="Evil",
            reg_value_data=r"C:\evil.exe",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=500)

        assert len(entities.risk_indicators) == 1
        indicator = entities.risk_indicators[0]
        assert indicator["type"] == "persistence"
        assert indicator["persistence_type"] == "registry_run_key"
        assert indicator["mitre_technique"] == "T1547.001"
        assert indicator["severity"] == "HIGH"
