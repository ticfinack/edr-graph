"""Tests for Phase 4 Commit 2: systemd unit file (4B).

Validates the systemd unit file has required directives.
"""

from pathlib import Path

import pytest

UNIT_FILE = Path(__file__).parent.parent / "deploy" / "edr-graph.service"


@pytest.fixture
def unit_content():
    return UNIT_FILE.read_text()


class TestSystemdUnit:
    def test_file_exists(self):
        assert UNIT_FILE.exists()

    def test_restart_always(self, unit_content):
        assert "Restart=always" in unit_content

    def test_restart_sec_1(self, unit_content):
        assert "RestartSec=1" in unit_content

    def test_watchdog_sec_30(self, unit_content):
        assert "WatchdogSec=30" in unit_content

    def test_runs_as_edr_graph_user(self, unit_content):
        assert "User=edr-graph" in unit_content

    def test_has_cap_net_admin(self, unit_content):
        assert "CAP_NET_ADMIN" in unit_content

    def test_has_cap_sys_ptrace(self, unit_content):
        assert "CAP_SYS_PTRACE" in unit_content

    def test_has_cap_audit_read(self, unit_content):
        assert "CAP_AUDIT_READ" in unit_content

    def test_has_no_dashboard_flag(self, unit_content):
        assert "--no-dashboard" in unit_content

    def test_has_json_log_format(self, unit_content):
        assert "--log-format json" in unit_content

    def test_has_install_section(self, unit_content):
        assert "[Install]" in unit_content
        assert "WantedBy=multi-user.target" in unit_content

    def test_hardening_no_new_privileges(self, unit_content):
        assert "NoNewPrivileges=yes" in unit_content

    def test_hardening_protect_system(self, unit_content):
        assert "ProtectSystem=strict" in unit_content

    def test_notify_type(self, unit_content):
        """Type=notify enables sd_notify watchdog integration."""
        assert "Type=notify" in unit_content
