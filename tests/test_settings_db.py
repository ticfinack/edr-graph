"""Tests for server/settings_db.py: SQLite settings database."""

import sqlite3
import threading

import pytest

from server.settings_db import SettingsDB


@pytest.fixture
def db(tmp_path):
    sdb = SettingsDB(tmp_path / "settings.db")
    yield sdb
    sdb.close()


class TestSchema:
    def test_tables_created(self, db):
        conn = db._conn()
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        assert "users" in tables
        assert "registration_keys" in tables
        assert "settings" in tables
        assert "agent_key_map" in tables

    def test_default_settings_seeded(self, db):
        s = db.get_all_settings()
        assert s["jwt_ttl_hours"] == "8"
        assert s["agent_default_response_mode"] == "learning"
        assert s["agent_default_dga_score_threshold"] == "0.6"

    def test_defaults_not_overwritten_on_reinit(self, db, tmp_path):
        db.set_setting("jwt_ttl_hours", "12")
        db2 = SettingsDB(tmp_path / "settings.db")
        assert db2.get_setting("jwt_ttl_hours") == "12"
        db2.close()


class TestUsers:
    def test_create_and_get_user(self, db):
        db.create_user("alice", "hash123", role="admin")
        user = db.get_user("alice")
        assert user["username"] == "alice"
        assert user["password_hash"] == "hash123"
        assert user["role"] == "admin"
        assert user["created_at"] > 0

    def test_list_users(self, db):
        db.create_user("alice", "h1")
        db.create_user("bob", "h2", role="analyst")
        users = db.list_users()
        assert len(users) == 2
        # list_users should NOT include password_hash
        assert "password_hash" not in users[0]

    def test_update_user_password(self, db):
        db.create_user("alice", "old_hash")
        ok = db.update_user("alice", password_hash="new_hash")
        assert ok
        assert db.get_user("alice")["password_hash"] == "new_hash"

    def test_update_user_role(self, db):
        db.create_user("alice", "hash", role="admin")
        ok = db.update_user("alice", role="viewer")
        assert ok
        assert db.get_user("alice")["role"] == "viewer"

    def test_update_nonexistent_user(self, db):
        assert db.update_user("ghost", role="admin") is False

    def test_delete_user(self, db):
        db.create_user("alice", "hash")
        assert db.delete_user("alice") is True
        assert db.get_user("alice") is None

    def test_delete_nonexistent_user(self, db):
        assert db.delete_user("ghost") is False

    def test_count_users(self, db):
        assert db.count_users() == 0
        db.create_user("alice", "h")
        assert db.count_users() == 1

    def test_duplicate_user_raises(self, db):
        db.create_user("alice", "h")
        with pytest.raises(sqlite3.IntegrityError):
            db.create_user("alice", "h2")

    def test_is_empty(self, db):
        assert db.is_empty() is True
        db.create_user("alice", "h")
        assert db.is_empty() is False


class TestRegistrationKeys:
    def test_create_and_list(self, db):
        result = db.create_registration_key(
            key="abc123", label="Test", created_by="admin"
        )
        assert result["key"] == "abc123"
        keys = db.list_registration_keys()
        assert len(keys) == 1
        assert keys[0]["label"] == "Test"
        assert keys[0]["status"] == "active"

    def test_validate_key(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        valid, reason = db.validate_registration_key("k1")
        assert valid is True
        assert reason == "ok"

    def test_validate_increments_use_count(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        db.validate_registration_key("k1")
        keys = db.list_registration_keys()
        assert keys[0]["use_count"] == 1

    def test_validate_invalid_key(self, db):
        valid, reason = db.validate_registration_key("nonexistent")
        assert valid is False
        assert reason == "invalid_key"

    def test_validate_revoked_key(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        db.revoke_registration_key("k1", revoked_by="admin")
        valid, reason = db.validate_registration_key("k1")
        assert valid is False
        assert reason == "key_revoked"

    def test_validate_expired_key(self, db):
        db.create_registration_key(
            key="k1", label="L", created_by="admin", expires_at=1
        )
        valid, reason = db.validate_registration_key("k1")
        assert valid is False
        assert reason == "key_expired"

    def test_validate_max_uses_exceeded(self, db):
        db.create_registration_key(
            key="k1", label="L", created_by="admin", max_uses=1
        )
        db.validate_registration_key("k1")
        valid, reason = db.validate_registration_key("k1")
        assert valid is False
        assert reason == "max_uses_exceeded"

    def test_revoke_key(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        ok = db.revoke_registration_key("k1", revoked_by="admin")
        assert ok is True
        keys = db.list_registration_keys()
        assert keys[0]["status"] == "revoked"
        assert keys[0]["revoked_by"] == "admin"

    def test_revoke_nonexistent_key(self, db):
        assert db.revoke_registration_key("nope", revoked_by="admin") is False

    def test_delete_key(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        assert db.delete_registration_key("k1") is True
        assert db.list_registration_keys() == []

    def test_delete_nonexistent_key(self, db):
        assert db.delete_registration_key("nope") is False

    def test_key_status_exhausted(self, db):
        db.create_registration_key(
            key="k1", label="L", created_by="admin", max_uses=1
        )
        db.validate_registration_key("k1")
        keys = db.list_registration_keys()
        assert keys[0]["status"] == "exhausted"

    def test_check_key_status_valid(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        valid, reason = db.check_key_status("k1")
        assert valid is True
        assert reason == "ok"

    def test_check_key_status_does_not_increment(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        db.check_key_status("k1")
        db.check_key_status("k1")
        db.check_key_status("k1")
        keys = db.list_registration_keys()
        assert keys[0]["use_count"] == 0

    def test_check_key_status_invalid(self, db):
        valid, reason = db.check_key_status("nonexistent")
        assert valid is False
        assert reason == "invalid_key"

    def test_check_key_status_revoked(self, db):
        db.create_registration_key(key="k1", label="L", created_by="admin")
        db.revoke_registration_key("k1", revoked_by="admin")
        valid, reason = db.check_key_status("k1")
        assert valid is False
        assert reason == "key_revoked"

    def test_check_key_status_expired(self, db):
        db.create_registration_key(
            key="k1", label="L", created_by="admin", expires_at=1
        )
        valid, reason = db.check_key_status("k1")
        assert valid is False
        assert reason == "key_expired"

    def test_check_key_status_exhausted_key_still_valid(self, db):
        """check_key_status allows exhausted keys (re-registration doesn't need a slot)."""
        db.create_registration_key(
            key="k1", label="L", created_by="admin", max_uses=1
        )
        db.validate_registration_key("k1")  # exhausts the key
        valid, reason = db.check_key_status("k1")
        assert valid is True  # re-registration should still work


class TestSettings:
    def test_get_set(self, db):
        db.set_setting("foo", "bar")
        assert db.get_setting("foo") == "bar"

    def test_get_nonexistent(self, db):
        assert db.get_setting("nonexistent") is None

    def test_overwrite(self, db):
        db.set_setting("foo", "bar")
        db.set_setting("foo", "baz")
        assert db.get_setting("foo") == "baz"

    def test_get_all_settings(self, db):
        s = db.get_all_settings()
        assert isinstance(s, dict)
        assert "jwt_ttl_hours" in s

    def test_agent_defaults(self, db):
        defaults = db.get_agent_defaults()
        assert "response_mode" in defaults
        assert defaults["response_mode"] == "learning"
        assert "analyzer_interval" in defaults

    def test_set_agent_default(self, db):
        db.set_agent_default("response_mode", "enforcing")
        defaults = db.get_agent_defaults()
        assert defaults["response_mode"] == "enforcing"


class TestAgentKeyMap:
    def test_set_and_get(self, db):
        db.set_agent_key("agent-1", "regkey-abc")
        assert db.get_agent_key("agent-1") == "regkey-abc"

    def test_get_nonexistent(self, db):
        assert db.get_agent_key("ghost") is None

    def test_overwrite(self, db):
        db.set_agent_key("agent-1", "key1")
        db.set_agent_key("agent-1", "key2")
        assert db.get_agent_key("agent-1") == "key2"


class TestThreadSafety:
    def test_concurrent_writes(self, tmp_path):
        db = SettingsDB(tmp_path / "settings.db")
        errors = []

        def writer(n):
            try:
                db.create_user(f"user_{n}", f"hash_{n}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert db.count_users() == 10
        db.close()

    def test_concurrent_key_validation_max_uses(self, tmp_path):
        """Atomic UPDATE prevents TOCTOU: exactly max_uses validations succeed."""
        db = SettingsDB(tmp_path / "settings.db")
        db.create_registration_key(key="race-key", label="Race", created_by="admin", max_uses=5)

        results = []

        def validate(_):
            ok, reason = db.validate_registration_key("race-key")
            results.append((ok, reason))

        threads = [threading.Thread(target=validate, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for ok, _ in results if ok)
        assert successes == 5
        failures = [(ok, reason) for ok, reason in results if not ok]
        assert all(reason == "max_uses_exceeded" for _, reason in failures)
        db.close()


class TestTagColorValidation:
    def test_create_tag_valid_color(self, db):
        tag = db.create_tag("colortest", color="#ff00aa")
        assert tag["color"] == "#ff00aa"

    def test_create_tag_invalid_color_rejected(self, db):
        with pytest.raises(ValueError, match="Invalid color"):
            db.create_tag("bad-color", color="red")

    def test_create_tag_invalid_color_script_injection(self, db):
        with pytest.raises(ValueError, match="Invalid color"):
            db.create_tag("xss", color="<script>alert(1)</script>")

    def test_create_tag_invalid_color_short_hex(self, db):
        with pytest.raises(ValueError, match="Invalid color"):
            db.create_tag("shorthex", color="#fff")

    def test_create_tag_invalid_color_long_hex(self, db):
        with pytest.raises(ValueError, match="Invalid color"):
            db.create_tag("longhex", color="#ff00aabb")

    def test_update_tag_valid_color(self, db):
        db.create_tag("updcolor")
        ok = db.update_tag("updcolor", color="#abcdef")
        assert ok is True
        assert db.get_tag("updcolor")["color"] == "#abcdef"

    def test_update_tag_invalid_color_rejected(self, db):
        db.create_tag("updcolor2")
        with pytest.raises(ValueError, match="Invalid color"):
            db.update_tag("updcolor2", color="not-a-color")


class TestGlobalCustomRules:
    def test_add_and_list(self, db):
        rule_id = db.add_global_custom_rule(
            action="block", stage="fast_path", rule_type="dst_ip",
            pattern="1.2.3.4", description="test rule", created_by="admin",
        )
        assert isinstance(rule_id, int)
        rules = db.list_global_custom_rules()
        assert len(rules) == 1
        assert rules[0]["action"] == "block"
        assert rules[0]["pattern"] == "1.2.3.4"
        assert rules[0]["created_by"] == "admin"

    def test_delete(self, db):
        rule_id = db.add_global_custom_rule(
            action="allow", stage="pre_graph", rule_type="process_name",
            pattern="safe.exe",
        )
        assert db.delete_global_custom_rule(rule_id) is True
        assert len(db.list_global_custom_rules()) == 0

    def test_delete_nonexistent(self, db):
        assert db.delete_global_custom_rule(99999) is False

    def test_invalid_action(self, db):
        with pytest.raises(ValueError, match="Invalid action"):
            db.add_global_custom_rule(
                action="nuke", stage="fast_path", rule_type="dst_ip", pattern="x",
            )

    def test_invalid_stage(self, db):
        with pytest.raises(ValueError, match="Invalid stage"):
            db.add_global_custom_rule(
                action="block", stage="invalid", rule_type="dst_ip", pattern="x",
            )

    def test_invalid_rule_type(self, db):
        with pytest.raises(ValueError, match="Invalid rule_type"):
            db.add_global_custom_rule(
                action="block", stage="fast_path", rule_type="bad_type", pattern="x",
            )

    def test_empty_pattern(self, db):
        with pytest.raises(ValueError, match="Pattern must not be empty"):
            db.add_global_custom_rule(
                action="block", stage="fast_path", rule_type="dst_ip", pattern="",
            )

    def test_resolve_agent_rules_includes_custom(self, db):
        db.add_global_custom_rule(
            action="block", stage="fast_path", rule_type="domain",
            pattern="evil.com", description="custom",
        )
        rules = db.resolve_agent_rules("agent-1")
        assert any(r["pattern"] == "evil.com" and r["description"] == "custom" for r in rules)


class TestDisabledSigmaRules:
    def test_table_exists(self, db):
        conn = db._conn()
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "disabled_sigma_rules" in tables

    def test_toggle_disable_and_enable(self, db):
        # First toggle: disable → returns True
        assert db.toggle_sigma_rule("process_name:bash") is True
        assert db.is_sigma_rule_disabled("process_name:bash") is True
        # Second toggle: enable → returns False
        assert db.toggle_sigma_rule("process_name:bash") is False
        assert db.is_sigma_rule_disabled("process_name:bash") is False

    def test_list_disabled(self, db):
        db.toggle_sigma_rule("process_name:bash")
        db.toggle_sigma_rule("file_path:/tmp/*")
        disabled = db.list_disabled_sigma_rules()
        assert len(disabled) == 2
        ids = {d["rule_id"] for d in disabled}
        assert "process_name:bash" in ids
        assert "file_path:/tmp/*" in ids

    def test_list_disabled_empty(self, db):
        assert db.list_disabled_sigma_rules() == []

    def test_toggle_empty_rule_id_raises(self, db):
        with pytest.raises(ValueError, match="rule_id is required"):
            db.toggle_sigma_rule("")

    def test_toggle_whitespace_rule_id_raises(self, db):
        with pytest.raises(ValueError, match="rule_id is required"):
            db.toggle_sigma_rule("   ")

    def test_disabled_by_stored(self, db):
        db.toggle_sigma_rule("process_name:test", disabled_by="admin")
        disabled = db.list_disabled_sigma_rules()
        assert disabled[0]["disabled_by"] == "admin"
        assert disabled[0]["disabled_at"] > 0

    def test_resolve_agent_rules_excludes_disabled(self, db):
        # Inject fake global rules
        db._global_rules = [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "bash", "chain_filter": "", "description": "rule1", "tags": []},
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "curl", "chain_filter": "", "description": "rule2", "tags": []},
            {"action": "block", "stage": "fast_path", "rule_type": "file_path", "pattern": "/tmp/*", "chain_filter": "", "description": "rule3", "tags": []},
        ]
        # Disable one rule
        db.toggle_sigma_rule("process_name:bash")
        rules = db.resolve_agent_rules("agent-1")
        patterns = [r["pattern"] for r in rules]
        assert "bash" not in patterns
        assert "curl" in patterns
        assert "/tmp/*" in patterns

    def test_resolve_excludes_multiple_disabled(self, db):
        db._global_rules = [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "a", "chain_filter": "", "description": "", "tags": []},
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "b", "chain_filter": "", "description": "", "tags": []},
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "c", "chain_filter": "", "description": "", "tags": []},
        ]
        db.toggle_sigma_rule("process_name:a")
        db.toggle_sigma_rule("process_name:c")
        rules = db.resolve_agent_rules("agent-1")
        patterns = [r["pattern"] for r in rules]
        assert patterns == ["b"]

    def test_re_enable_restores_to_resolve(self, db):
        db._global_rules = [
            {"action": "block", "stage": "fast_path", "rule_type": "process_name", "pattern": "bash", "chain_filter": "", "description": "", "tags": []},
        ]
        db.toggle_sigma_rule("process_name:bash")  # disable
        assert len(db.resolve_agent_rules("agent-1")) == 0
        db.toggle_sigma_rule("process_name:bash")  # re-enable
        assert len(db.resolve_agent_rules("agent-1")) == 1


class TestGlobalIntelSuppressions:
    def test_add_and_list(self, db):
        row = db.add_global_intel_suppression(
            indicator_type="ip", pattern="8.8.8.8",
            reason="Google DNS", created_by="admin",
        )
        assert row["indicator_type"] == "ip"
        assert row["pattern"] == "8.8.8.8"
        items = db.list_global_intel_suppressions()
        assert len(items) == 1

    def test_add_normalizes_pattern(self, db):
        row = db.add_global_intel_suppression(
            indicator_type="domain", pattern="  CDN.Example.COM  ",
        )
        assert row["pattern"] == "cdn.example.com"

    def test_delete(self, db):
        row = db.add_global_intel_suppression(
            indicator_type="hash", pattern="abc123",
        )
        assert db.delete_global_intel_suppression(row["id"]) is True
        assert len(db.list_global_intel_suppressions()) == 0

    def test_delete_nonexistent(self, db):
        assert db.delete_global_intel_suppression(99999) is False

    def test_uniqueness_constraint(self, db):
        db.add_global_intel_suppression(indicator_type="ip", pattern="1.1.1.1")
        with pytest.raises(Exception):
            db.add_global_intel_suppression(indicator_type="ip", pattern="1.1.1.1")

    def test_invalid_type(self, db):
        with pytest.raises(ValueError, match="Invalid indicator_type"):
            db.add_global_intel_suppression(indicator_type="url", pattern="x")

    def test_empty_pattern(self, db):
        with pytest.raises(ValueError, match="Pattern must not be empty"):
            db.add_global_intel_suppression(indicator_type="ip", pattern="  ")

    def test_resolve_agent_config_includes_suppressions(self, db):
        db.add_global_intel_suppression(
            indicator_type="ip", pattern="10.0.0.1", reason="test",
        )
        config = db.resolve_agent_config("agent-1")
        assert "suppressions" in config
        assert len(config["suppressions"]) == 1
        assert config["suppressions"][0]["pattern"] == "10.0.0.1"
