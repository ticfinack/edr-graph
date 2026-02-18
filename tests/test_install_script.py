"""Tests for Phase 5 Commit 2: Linux install script (5B)."""

from pathlib import Path

import pytest

INSTALL_SCRIPT = Path(__file__).parent.parent / "deploy" / "install.sh"


@pytest.fixture
def script_content():
    return INSTALL_SCRIPT.read_text()


class TestInstallScript:
    def test_file_exists(self):
        assert INSTALL_SCRIPT.exists()

    def test_is_executable(self):
        import os
        assert os.access(INSTALL_SCRIPT, os.X_OK)

    def test_has_shebang(self, script_content):
        assert script_content.startswith("#!/")

    def test_set_euo_pipefail(self, script_content):
        """Script uses strict bash error handling."""
        assert "set -euo pipefail" in script_content

    def test_checks_root(self, script_content):
        assert "EUID" in script_content

    def test_checks_python_version(self, script_content):
        assert "python3" in script_content
        assert "3.11" in script_content or "version_info" in script_content

    def test_creates_service_user(self, script_content):
        assert "useradd" in script_content
        assert "edr-graph" in script_content

    def test_creates_required_directories(self, script_content):
        for d in ["/opt/edr-graph", "/etc/edr-graph", "/var/lib/edr-graph",
                  "/var/edr-graph/quarantine"]:
            assert d in script_content

    def test_installs_systemd_service(self, script_content):
        assert "systemctl" in script_content
        assert "daemon-reload" in script_content
        assert "enable" in script_content

    def test_starts_and_verifies(self, script_content):
        assert "systemctl start" in script_content
        assert "is-active" in script_content

    def test_sets_permissions(self, script_content):
        assert "chown" in script_content
        assert "chmod" in script_content

    def test_writes_initial_config(self, script_content):
        assert "config.yaml" in script_content
