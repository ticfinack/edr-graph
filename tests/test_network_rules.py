"""Tests for network-distributed rule enforcement on agent-side stages.

Verifies that ResponseAllowlist, ResponseBlocklist, and FastBlocklist
correctly handle hot-reloaded network rules from the fleet server.
"""


import pytest

from agent.response.baseline import ResponseAllowlist, ResponseBlocklist


@pytest.fixture
def db_path(tmp_path):
    """Create a SQLite database with the required tables."""
    import sqlite3

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS response_allowlist ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  rule_type TEXT NOT NULL,"
        "  pattern TEXT NOT NULL,"
        "  description TEXT NOT NULL DEFAULT '',"
        "  chain_filter TEXT NOT NULL DEFAULT ''"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS response_blocklist ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  rule_type TEXT NOT NULL,"
        "  pattern TEXT NOT NULL,"
        "  description TEXT NOT NULL DEFAULT '',"
        "  chain_filter TEXT NOT NULL DEFAULT ''"
        ")"
    )
    conn.commit()
    conn.close()
    return db


class TestResponseAllowlistNetworkRules:
    def test_set_and_get_network_rules(self, db_path):
        al = ResponseAllowlist(db_path)
        rules = [
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": "", "description": "trusted"},
        ]
        al.set_network_rules(rules)
        assert len(al.get_network_rules()) == 1
        assert al.get_network_rules()[0]["pattern"] == "10.0.0.1"

    def test_network_rule_checked_in_is_allowed(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": "", "description": "trusted"},
        ])
        matched, desc = al.is_allowed(dst_ip="10.0.0.1")
        assert matched is True
        assert desc == "trusted"

    def test_network_rule_no_match(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": "", "description": "trusted"},
        ])
        matched, _ = al.is_allowed(dst_ip="192.168.1.1")
        assert matched is False

    def test_network_rule_process_name(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "process_name", "pattern": "sshd", "chain_filter": "", "description": "ssh allowed"},
        ])
        matched, desc = al.is_allowed(process_name="sshd")
        assert matched is True

    def test_network_rule_domain(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "domain", "pattern": "internal.corp", "chain_filter": "", "description": "internal"},
        ])
        matched, _ = al.is_allowed(domain="internal.corp")
        assert matched is True

    def test_atomic_replacement(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": ""},
        ])
        assert al.is_allowed(dst_ip="10.0.0.1")[0] is True

        # Replace with different rules
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "192.168.1.1", "chain_filter": ""},
        ])
        assert al.is_allowed(dst_ip="10.0.0.1")[0] is False
        assert al.is_allowed(dst_ip="192.168.1.1")[0] is True

    def test_sqlite_rules_unaffected(self, db_path):
        al = ResponseAllowlist(db_path)
        # Add a local SQLite rule
        al.add_rule("dst_ip", "172.16.0.1", description="local rule")

        # Set network rules
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": ""},
        ])

        # Both should work
        assert al.is_allowed(dst_ip="172.16.0.1")[0] is True
        assert al.is_allowed(dst_ip="10.0.0.1")[0] is True

        # Clear network rules — SQLite rule remains
        al.set_network_rules([])
        assert al.is_allowed(dst_ip="172.16.0.1")[0] is True
        assert al.is_allowed(dst_ip="10.0.0.1")[0] is False

    def test_graph_filterable_includes_network_rules(self, db_path):
        al = ResponseAllowlist(db_path)
        al.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "10.0.0.1", "chain_filter": ""},
            {"rule_type": "finding_title", "pattern": "test*", "chain_filter": ""},  # not graph-filterable
            {"rule_type": "process_name", "pattern": "sshd", "chain_filter": "** > sshd"},  # has chain_filter
        ])
        rules = al.get_graph_filterable_rules()
        # Only dst_ip (no chain_filter, graph-filterable type) should be included
        assert len(rules) == 1
        assert rules[0]["pattern"] == "10.0.0.1"


class TestResponseBlocklistNetworkRules:
    def test_set_and_get_network_rules(self, db_path):
        bl = ResponseBlocklist(db_path)
        rules = [
            {"rule_type": "process_name", "pattern": "mimikatz", "chain_filter": "", "description": "malware"},
        ]
        bl.set_network_rules(rules)
        assert len(bl.get_network_rules()) == 1

    def test_network_rule_checked_in_is_blocked(self, db_path):
        bl = ResponseBlocklist(db_path)
        bl.set_network_rules([
            {"rule_type": "process_name", "pattern": "mimikatz", "chain_filter": "", "description": "malware"},
        ])
        matched, desc = bl.is_blocked(process_name="mimikatz")
        assert matched is True
        assert desc == "malware"

    def test_network_rule_dst_cidr(self, db_path):
        bl = ResponseBlocklist(db_path)
        bl.set_network_rules([
            {"rule_type": "dst_cidr", "pattern": "198.51.100.0/24", "chain_filter": "", "description": "bad range"},
        ])
        matched, _ = bl.is_blocked(dst_ip="198.51.100.42")
        assert matched is True
        matched, _ = bl.is_blocked(dst_ip="192.168.1.1")
        assert matched is False

    def test_atomic_replacement(self, db_path):
        bl = ResponseBlocklist(db_path)
        bl.set_network_rules([
            {"rule_type": "domain", "pattern": "evil.com", "chain_filter": ""},
        ])
        assert bl.is_blocked(domain="evil.com")[0] is True

        bl.set_network_rules([
            {"rule_type": "domain", "pattern": "worse.com", "chain_filter": ""},
        ])
        assert bl.is_blocked(domain="evil.com")[0] is False
        assert bl.is_blocked(domain="worse.com")[0] is True

    def test_sqlite_rules_unaffected(self, db_path):
        bl = ResponseBlocklist(db_path)
        bl.add_rule("domain", "local-evil.com", description="local rule")

        bl.set_network_rules([
            {"rule_type": "domain", "pattern": "network-evil.com", "chain_filter": ""},
        ])

        assert bl.is_blocked(domain="local-evil.com")[0] is True
        assert bl.is_blocked(domain="network-evil.com")[0] is True

        bl.set_network_rules([])
        assert bl.is_blocked(domain="local-evil.com")[0] is True
        assert bl.is_blocked(domain="network-evil.com")[0] is False


class TestFastBlocklistNetworkRules:
    def test_set_network_rules_invalidates(self, db_path):
        bl = ResponseBlocklist(db_path)
        from agent.processor.synchronous_enforcer import FastBlocklist

        fb = FastBlocklist(bl)
        fb.set_network_rules([
            {"rule_type": "process_name", "pattern": "evil", "chain_filter": "", "description": "test"},
        ])
        assert fb._invalidated is True

    def test_network_rules_compiled(self, db_path):
        bl = ResponseBlocklist(db_path)
        from agent.processor.synchronous_enforcer import FastBlocklist

        fb = FastBlocklist(bl)
        fb.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "1.2.3.4", "chain_filter": ""},
            {"rule_type": "domain", "pattern": "evil.com", "chain_filter": ""},
            {"rule_type": "process_name", "pattern": "hack*", "chain_filter": "", "description": "hacking tools"},
        ])
        # Force compilation
        fb._refresh_if_stale()

        assert "1.2.3.4" in fb._ips
        assert "evil.com" in fb._domains
        assert len(fb._process_names) == 1
        assert fb._has_rules is True

    def test_atomic_replacement_recompiles(self, db_path):
        bl = ResponseBlocklist(db_path)
        from agent.processor.synchronous_enforcer import FastBlocklist

        fb = FastBlocklist(bl)
        fb.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "1.2.3.4", "chain_filter": ""},
        ])
        fb._refresh_if_stale()
        assert "1.2.3.4" in fb._ips

        fb.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "5.6.7.8", "chain_filter": ""},
        ])
        fb._refresh_if_stale()
        assert "1.2.3.4" not in fb._ips
        assert "5.6.7.8" in fb._ips

    def test_sqlite_and_network_rules_merged(self, db_path):
        bl = ResponseBlocklist(db_path)
        bl.add_rule("dst_ip", "10.0.0.1", description="local")

        from agent.processor.synchronous_enforcer import FastBlocklist

        fb = FastBlocklist(bl)
        fb.set_network_rules([
            {"rule_type": "dst_ip", "pattern": "1.2.3.4", "chain_filter": ""},
        ])
        fb._refresh_if_stale()

        assert "10.0.0.1" in fb._ips
        assert "1.2.3.4" in fb._ips
