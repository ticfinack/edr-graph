"""Tests for tag-based agent policies in server/settings_db.py."""

import sqlite3

import pytest

from server.settings_db import SettingsDB


@pytest.fixture
def db(tmp_path):
    sdb = SettingsDB(tmp_path / "settings.db")
    yield sdb
    sdb.close()


class TestTagsCRUD:
    def test_create_tag(self, db):
        tag = db.create_tag("production", description="Prod hosts", color="#ef4444", priority=10)
        assert tag["tag_name"] == "production"
        assert tag["description"] == "Prod hosts"
        assert tag["color"] == "#ef4444"
        assert tag["priority"] == 10
        assert tag["created_at"] > 0

    def test_create_tag_defaults(self, db):
        tag = db.create_tag("dev")
        assert tag["color"] == "#3b82f6"
        assert tag["priority"] == 0

    def test_create_tag_invalid_name(self, db):
        with pytest.raises(ValueError):
            db.create_tag("UPPERCASE")
        with pytest.raises(ValueError):
            db.create_tag("")
        with pytest.raises(ValueError):
            db.create_tag("-starts-with-dash")
        with pytest.raises(ValueError):
            db.create_tag("a" * 51)

    def test_create_tag_valid_names(self, db):
        db.create_tag("a")
        db.create_tag("my-tag")
        db.create_tag("tag_123")
        db.create_tag("0day")

    def test_create_duplicate_tag_raises(self, db):
        db.create_tag("prod")
        with pytest.raises(sqlite3.IntegrityError):
            db.create_tag("prod")

    def test_list_tags_empty(self, db):
        assert db.list_tags() == []

    def test_list_tags_with_agent_count(self, db):
        db.create_tag("prod", priority=10)
        db.create_tag("dev", priority=0)
        db.set_agent_key("agent-1", "key1")
        db.assign_tag("agent-1", "prod")
        db.assign_tag("agent-1", "dev")
        db.set_agent_key("agent-2", "key2")
        db.assign_tag("agent-2", "prod")

        tags = db.list_tags()
        assert len(tags) == 2
        # Sorted by priority ASC: dev(0), prod(10)
        assert tags[0]["tag_name"] == "dev"
        assert tags[0]["agent_count"] == 1
        assert tags[1]["tag_name"] == "prod"
        assert tags[1]["agent_count"] == 2

    def test_get_tag(self, db):
        db.create_tag("staging", description="Staging env")
        tag = db.get_tag("staging")
        assert tag["tag_name"] == "staging"
        assert tag["description"] == "Staging env"

    def test_get_tag_nonexistent(self, db):
        assert db.get_tag("ghost") is None

    def test_update_tag(self, db):
        db.create_tag("prod")
        ok = db.update_tag("prod", description="Production", color="#ff0000", priority=99)
        assert ok is True
        tag = db.get_tag("prod")
        assert tag["description"] == "Production"
        assert tag["color"] == "#ff0000"
        assert tag["priority"] == 99

    def test_update_tag_partial(self, db):
        db.create_tag("prod", description="old", color="#111", priority=5)
        db.update_tag("prod", priority=50)
        tag = db.get_tag("prod")
        assert tag["description"] == "old"
        assert tag["color"] == "#111"
        assert tag["priority"] == 50

    def test_update_tag_nonexistent(self, db):
        assert db.update_tag("ghost", description="x") is False

    def test_delete_tag(self, db):
        db.create_tag("temp")
        assert db.delete_tag("temp") is True
        assert db.get_tag("temp") is None

    def test_delete_tag_nonexistent(self, db):
        assert db.delete_tag("ghost") is False

    def test_delete_tag_cascades_agent_tags(self, db):
        db.create_tag("prod")
        db.assign_tag("agent-1", "prod")
        db.delete_tag("prod")
        assert db.get_agent_tags("agent-1") == []

    def test_delete_tag_cascades_policies(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {"response_mode": "enforcing"})
        db.delete_tag("prod")
        # Tag gone, so policy should be gone too
        assert db.get_tag_policy("prod") == {}


class TestAgentTagAssignment:
    def test_assign_and_get_tags(self, db):
        db.create_tag("prod", priority=10)
        db.create_tag("monitored", priority=5)
        db.assign_tag("agent-1", "prod", assigned_by="admin")
        db.assign_tag("agent-1", "monitored", assigned_by="admin")

        tags = db.get_agent_tags("agent-1")
        assert len(tags) == 2
        # Sorted by priority ASC: monitored(5), prod(10)
        assert tags[0]["tag_name"] == "monitored"
        assert tags[1]["tag_name"] == "prod"
        assert tags[1]["assigned_by"] == "admin"

    def test_assign_tag_idempotent(self, db):
        db.create_tag("prod")
        db.assign_tag("agent-1", "prod")
        db.assign_tag("agent-1", "prod")  # Should not raise
        tags = db.get_agent_tags("agent-1")
        assert len(tags) == 1

    def test_assign_nonexistent_tag_raises(self, db):
        with pytest.raises(ValueError, match="Tag does not exist"):
            db.assign_tag("agent-1", "ghost")

    def test_remove_tag(self, db):
        db.create_tag("prod")
        db.assign_tag("agent-1", "prod")
        assert db.remove_tag("agent-1", "prod") is True
        assert db.get_agent_tags("agent-1") == []

    def test_remove_tag_not_assigned(self, db):
        db.create_tag("prod")
        assert db.remove_tag("agent-1", "prod") is False

    def test_get_tag_agents(self, db):
        db.create_tag("prod")
        db.assign_tag("agent-1", "prod")
        db.assign_tag("agent-2", "prod")
        agents = db.get_tag_agents("prod")
        assert sorted(agents) == ["agent-1", "agent-2"]

    def test_get_tag_agents_empty(self, db):
        db.create_tag("prod")
        assert db.get_tag_agents("prod") == []

    def test_get_agent_tags_no_tags(self, db):
        assert db.get_agent_tags("agent-1") == []

    def test_get_bulk_agent_tags(self, db):
        db.create_tag("prod", priority=10)
        db.create_tag("dev", priority=0)
        db.assign_tag("agent-1", "prod")
        db.assign_tag("agent-1", "dev")
        db.assign_tag("agent-2", "prod")

        result = db.get_bulk_agent_tags(["agent-1", "agent-2", "agent-3"])
        assert len(result["agent-1"]) == 2
        assert result["agent-1"][0]["tag_name"] == "dev"  # lower priority first
        assert len(result["agent-2"]) == 1
        assert result["agent-3"] == []

    def test_get_bulk_agent_tags_empty(self, db):
        assert db.get_bulk_agent_tags([]) == {}


class TestTagPolicies:
    def test_set_and_get_policy(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {"response_mode": "enforcing", "auto_respond": "true"})
        policy = db.get_tag_policy("prod")
        assert policy == {"response_mode": "enforcing", "auto_respond": "true"}

    def test_set_policy_replaces(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {"response_mode": "enforcing"})
        db.set_tag_policy("prod", {"auto_respond": "true"})
        policy = db.get_tag_policy("prod")
        assert policy == {"auto_respond": "true"}
        assert "response_mode" not in policy

    def test_set_policy_filters_invalid_keys(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {
            "response_mode": "enforcing",
            "invalid_key": "should_be_ignored",
            "another_bad": "also_ignored",
        })
        policy = db.get_tag_policy("prod")
        assert policy == {"response_mode": "enforcing"}

    def test_set_policy_nonexistent_tag(self, db):
        with pytest.raises(ValueError, match="Tag does not exist"):
            db.set_tag_policy("ghost", {"response_mode": "enforcing"})

    def test_get_policy_empty(self, db):
        db.create_tag("prod")
        assert db.get_tag_policy("prod") == {}

    def test_set_policy_empty_clears(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {"response_mode": "enforcing"})
        db.set_tag_policy("prod", {})
        assert db.get_tag_policy("prod") == {}


class TestConfigResolution:
    def test_no_tags_returns_defaults(self, db):
        config = db.resolve_agent_config("agent-1")
        assert config["response_mode"] == "learning"
        assert config["auto_respond"] == "false"

    def test_single_tag_override(self, db):
        db.create_tag("prod")
        db.set_tag_policy("prod", {"response_mode": "enforcing", "auto_respond": "true"})
        db.assign_tag("agent-1", "prod")

        config = db.resolve_agent_config("agent-1")
        assert config["response_mode"] == "enforcing"
        assert config["auto_respond"] == "true"
        # Non-overridden settings stay default
        assert config["analyzer_interval"] == "60.0"

    def test_multi_tag_priority(self, db):
        db.create_tag("base", priority=0)
        db.create_tag("prod", priority=10)
        db.set_tag_policy("base", {"response_mode": "passive", "auto_respond": "false"})
        db.set_tag_policy("prod", {"response_mode": "enforcing"})
        db.assign_tag("agent-1", "base")
        db.assign_tag("agent-1", "prod")

        config = db.resolve_agent_config("agent-1")
        # prod (priority 10) overwrites base (priority 0) for response_mode
        assert config["response_mode"] == "enforcing"
        # auto_respond only set by base, so it applies
        assert config["auto_respond"] == "false"

    def test_partial_override(self, db):
        db.create_tag("custom")
        db.set_tag_policy("custom", {"graph_ttl_hours": "48"})
        db.assign_tag("agent-1", "custom")

        config = db.resolve_agent_config("agent-1")
        assert config["graph_ttl_hours"] == "48"
        # Everything else unchanged
        assert config["response_mode"] == "learning"
        assert config["collector_poll_interval"] == "1.0"

    def test_deterministic_tiebreak(self, db):
        """Same-priority tags are resolved alphabetically (deterministic)."""
        db.create_tag("alpha", priority=5)
        db.create_tag("beta", priority=5)
        db.set_tag_policy("alpha", {"response_mode": "passive"})
        db.set_tag_policy("beta", {"response_mode": "enforcing"})
        db.assign_tag("agent-1", "alpha")
        db.assign_tag("agent-1", "beta")

        config = db.resolve_agent_config("agent-1")
        # Same priority, alphabetical order: alpha then beta, beta overwrites
        assert config["response_mode"] == "enforcing"

    def test_three_tag_layering(self, db):
        db.create_tag("base", priority=0)
        db.create_tag("team", priority=5)
        db.create_tag("override", priority=10)
        db.set_tag_policy("base", {
            "response_mode": "learning",
            "auto_respond": "false",
            "graph_ttl_hours": "12",
        })
        db.set_tag_policy("team", {
            "response_mode": "passive",
            "analyzer_interval": "30.0",
        })
        db.set_tag_policy("override", {
            "response_mode": "enforcing",
        })
        db.assign_tag("agent-1", "base")
        db.assign_tag("agent-1", "team")
        db.assign_tag("agent-1", "override")

        config = db.resolve_agent_config("agent-1")
        assert config["response_mode"] == "enforcing"  # override wins
        assert config["analyzer_interval"] == "30.0"    # from team
        assert config["auto_respond"] == "false"         # from base
        assert config["graph_ttl_hours"] == "12"         # from base

    def test_agent_without_tags_backward_compatible(self, db):
        """resolve_agent_config returns agent defaults plus empty rules when no tags."""
        defaults = db.get_agent_defaults()
        resolved = db.resolve_agent_config("untagged-agent")
        for k, v in defaults.items():
            assert resolved[k] == v
        assert resolved["rules"] == []

    def test_tag_with_no_policy_no_effect(self, db):
        db.create_tag("empty-tag")
        db.assign_tag("agent-1", "empty-tag")
        config = db.resolve_agent_config("agent-1")
        defaults = db.get_agent_defaults()
        # Compare scalar settings (rules key is always present in resolved config)
        for k, v in defaults.items():
            assert config[k] == v

    def test_resolve_includes_rules_key(self, db):
        config = db.resolve_agent_config("agent-1")
        assert "rules" in config
        assert isinstance(config["rules"], list)


class TestTagRules:
    def test_set_and_get_rules(self, db):
        db.create_tag("prod")
        rules = [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
            {"action": "allow", "stage": "pre_graph", "rule_type": "dst_ip", "pattern": "10.0.0.1"},
        ]
        db.set_tag_rules("prod", rules)
        got = db.get_tag_rules("prod")
        assert len(got) == 2
        assert got[0]["action"] == "block"
        assert got[0]["pattern"] == "mimikatz"
        assert got[1]["action"] == "allow"
        assert got[1]["pattern"] == "10.0.0.1"

    def test_set_rules_replaces(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
        ])
        db.set_tag_rules("prod", [
            {"action": "allow", "stage": "response", "rule_type": "domain", "pattern": "example.com"},
        ])
        got = db.get_tag_rules("prod")
        assert len(got) == 1
        assert got[0]["action"] == "allow"
        assert got[0]["pattern"] == "example.com"

    def test_set_rules_filters_invalid_action(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "invalid", "stage": "fast_path", "rule_type": "process_name", "pattern": "foo"},
        ])
        assert db.get_tag_rules("prod") == []

    def test_set_rules_filters_invalid_stage(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "invalid", "rule_type": "process_name", "pattern": "foo"},
        ])
        assert db.get_tag_rules("prod") == []

    def test_set_rules_filters_invalid_rule_type(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "invalid", "pattern": "foo"},
        ])
        assert db.get_tag_rules("prod") == []

    def test_set_rules_filters_empty_pattern(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": ""},
        ])
        assert db.get_tag_rules("prod") == []

    def test_set_rules_nonexistent_tag(self, db):
        with pytest.raises(ValueError, match="Tag does not exist"):
            db.set_tag_rules("ghost", [])

    def test_get_rules_empty(self, db):
        db.create_tag("prod")
        assert db.get_tag_rules("prod") == []

    def test_set_rules_preserves_chain_filter_and_description(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {
                "action": "block", "stage": "fast_path", "rule_type": "process_name",
                "pattern": "bash", "chain_filter": "** > rsync > bash",
                "description": "Block rsync shells",
            },
        ])
        got = db.get_tag_rules("prod")
        assert got[0]["chain_filter"] == "** > rsync > bash"
        assert got[0]["description"] == "Block rsync shells"

    def test_delete_tag_cascades_rules(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "evil"},
        ])
        db.delete_tag("prod")
        assert db.get_tag_rules("prod") == []

    def test_resolve_agent_rules_no_tags(self, db):
        rules = db.resolve_agent_rules("agent-1")
        assert rules == []

    def test_resolve_agent_rules_single_tag(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
        ])
        db.assign_tag("agent-1", "prod")
        rules = db.resolve_agent_rules("agent-1")
        assert len(rules) == 1
        assert rules[0]["pattern"] == "mimikatz"

    def test_resolve_agent_rules_multi_tag_union(self, db):
        db.create_tag("prod")
        db.create_tag("secure")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "mimikatz"},
        ])
        db.set_tag_rules("secure", [
            {"action": "block", "stage": "fast_path", "rule_type": "dst_ip", "pattern": "1.2.3.4"},
        ])
        db.assign_tag("agent-1", "prod")
        db.assign_tag("agent-1", "secure")
        rules = db.resolve_agent_rules("agent-1")
        assert len(rules) == 2
        patterns = {r["pattern"] for r in rules}
        assert patterns == {"mimikatz", "1.2.3.4"}

    def test_resolve_agent_config_includes_rules(self, db):
        db.create_tag("prod")
        db.set_tag_rules("prod", [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "evil"},
        ])
        db.assign_tag("agent-1", "prod")
        config = db.resolve_agent_config("agent-1")
        assert len(config["rules"]) == 1
        assert config["rules"][0]["pattern"] == "evil"


class TestGlobalRules:
    def test_global_rules_included_in_resolve(self, tmp_path):
        """Global rules appear in resolved config for all agents."""
        yaml_path = tmp_path / "blocklist.yml"
        yaml_path.write_text(
            "rules:\n"
            "- rule_type: process_name\n"
            "  pattern: mimikatz\n"
            "  description: test rule\n"
            "  chain_filter: ''\n"
        )
        sdb = SettingsDB(tmp_path / "settings.db", global_rules_path=yaml_path)
        rules = sdb.resolve_agent_rules("any-agent")
        assert len(rules) == 1
        assert rules[0]["action"] == "block"
        assert rules[0]["stage"] == "fast_path"
        assert rules[0]["pattern"] == "mimikatz"
        sdb.close()

    def test_global_rules_plus_tag_rules(self, tmp_path):
        yaml_path = tmp_path / "blocklist.yml"
        yaml_path.write_text(
            "rules:\n"
            "- rule_type: process_name\n"
            "  pattern: global-evil\n"
            "  description: global\n"
            "  chain_filter: ''\n"
        )
        sdb = SettingsDB(tmp_path / "settings.db", global_rules_path=yaml_path)
        sdb.create_tag("custom")
        sdb.set_tag_rules("custom", [
            {"action": "allow", "stage": "pre_graph", "rule_type": "dst_ip", "pattern": "10.0.0.1"},
        ])
        sdb.assign_tag("agent-1", "custom")
        rules = sdb.resolve_agent_rules("agent-1")
        assert len(rules) == 2
        sdb.close()

    def test_missing_yaml_graceful(self, tmp_path):
        sdb = SettingsDB(tmp_path / "settings.db", global_rules_path=tmp_path / "nonexistent.yml")
        assert sdb.resolve_agent_rules("agent-1") == []
        sdb.close()

    def test_no_global_rules_path(self, tmp_path):
        sdb = SettingsDB(tmp_path / "settings.db")
        assert sdb.resolve_agent_rules("agent-1") == []
        sdb.close()
