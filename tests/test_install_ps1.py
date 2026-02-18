"""Tests for Phase 5 Commit 3: Windows install script (5B)."""

from pathlib import Path

import pytest

INSTALL_SCRIPT = Path(__file__).parent.parent / "deploy" / "install.ps1"


@pytest.fixture
def script_content():
    return INSTALL_SCRIPT.read_text()


class TestWindowsInstallScript:
    def test_file_exists(self):
        assert INSTALL_SCRIPT.exists()

    def test_requires_admin(self, script_content):
        assert "#Requires -RunAsAdministrator" in script_content

    def test_checks_python_version(self, script_content):
        assert "python" in script_content.lower()
        assert "3.11" in script_content or "version" in script_content.lower()

    def test_creates_directories(self, script_content):
        assert "New-Item" in script_content
        assert "Directory" in script_content

    def test_creates_venv(self, script_content):
        assert "venv" in script_content

    def test_installs_dependencies(self, script_content):
        assert "pip" in script_content

    def test_writes_config(self, script_content):
        assert "config.yaml" in script_content

    def test_sets_permissions(self, script_content):
        assert "Set-Acl" in script_content or "ACL" in script_content

    def test_installs_service(self, script_content):
        assert "EDRGraphAgent" in script_content
        assert "windows_service" in script_content

    def test_starts_service(self, script_content):
        assert "Start-Service" in script_content

    def test_verifies_running(self, script_content):
        assert "Get-Service" in script_content

    def test_no_hardcoded_api_keys(self, script_content):
        assert "sk-" not in script_content
