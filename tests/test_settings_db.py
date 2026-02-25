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
