"""Tests for Neo4j → SQLite migration in server/app.py."""

from unittest.mock import MagicMock

import pytest

from server.app import _migrate_neo4j_to_sqlite
from server.settings_db import SettingsDB


@pytest.fixture
def settings_db(tmp_path):
    sdb = SettingsDB(tmp_path / "settings.db")
    yield sdb
    sdb.close()


@pytest.fixture
def mock_neo4j():
    neo4j = MagicMock()
    neo4j.get_all_dashboard_users.return_value = [
        {
            "username": "alice",
            "password_hash": "$2b$12$fakehash",
            "role": "admin",
            "created_at": 1700000000,
        },
        {
            "username": "bob",
            "password_hash": "$2b$12$otherhash",
            "role": "analyst",
            "created_at": 1700000001,
        },
    ]
    neo4j.get_all_registration_keys.return_value = [
        {
            "key": "regkey123",
            "label": "Production",
            "created_at": 1700000000,
            "created_by": "alice",
            "expires_at": None,
            "max_uses": 10,
            "use_count": 3,
            "revoked": False,
            "revoked_at": None,
            "revoked_by": None,
        },
    ]
    return neo4j


class TestMigration:
    def test_migrates_users(self, settings_db, mock_neo4j):
        _migrate_neo4j_to_sqlite(mock_neo4j, settings_db)

        assert settings_db.count_users() == 2
        alice = settings_db.get_user("alice")
        assert alice["role"] == "admin"
        assert alice["password_hash"] == "$2b$12$fakehash"

    def test_migrates_keys(self, settings_db, mock_neo4j):
        _migrate_neo4j_to_sqlite(mock_neo4j, settings_db)

        keys = settings_db.list_registration_keys()
        assert len(keys) == 1
        assert keys[0]["key"] == "regkey123"
        assert keys[0]["use_count"] == 3

    def test_skips_when_sqlite_has_data(self, settings_db, mock_neo4j):
        settings_db.create_user("existing", "hash", role="admin")
        _migrate_neo4j_to_sqlite(mock_neo4j, settings_db)

        # Should not have migrated neo4j users since SQLite already has data
        assert settings_db.count_users() == 1
        assert settings_db.get_user("alice") is None

    def test_skips_when_neo4j_has_no_data(self, settings_db):
        neo4j = MagicMock()
        neo4j.get_all_dashboard_users.return_value = []
        neo4j.get_all_registration_keys.return_value = []

        _migrate_neo4j_to_sqlite(neo4j, settings_db)
        assert settings_db.count_users() == 0

    def test_handles_neo4j_query_failure(self, settings_db):
        neo4j = MagicMock()
        neo4j.get_all_dashboard_users.side_effect = Exception("Neo4j down")

        # Should not raise
        _migrate_neo4j_to_sqlite(neo4j, settings_db)
        assert settings_db.count_users() == 0

    def test_handles_partial_user_failure(self, settings_db):
        neo4j = MagicMock()
        neo4j.get_all_dashboard_users.return_value = [
            {"username": "alice", "password_hash": "h1", "role": "admin", "created_at": 1},
            {"username": "alice", "password_hash": "h2", "role": "admin", "created_at": 2},  # duplicate
        ]
        neo4j.get_all_registration_keys.return_value = []

        _migrate_neo4j_to_sqlite(neo4j, settings_db)
        # First one should succeed, second should be logged and skipped
        assert settings_db.count_users() == 1

    def test_migrates_revoked_key(self, settings_db):
        neo4j = MagicMock()
        neo4j.get_all_dashboard_users.return_value = [
            {"username": "admin", "password_hash": "h", "role": "admin", "created_at": 1}
        ]
        neo4j.get_all_registration_keys.return_value = [
            {
                "key": "revokedkey",
                "label": "Old",
                "created_at": 1,
                "created_by": "admin",
                "expires_at": None,
                "max_uses": None,
                "use_count": 5,
                "revoked": True,
                "revoked_at": 2,
                "revoked_by": "admin",
            }
        ]

        _migrate_neo4j_to_sqlite(neo4j, settings_db)
        keys = settings_db.list_registration_keys()
        assert len(keys) == 1
        assert keys[0]["status"] == "revoked"
        assert keys[0]["revoked_by"] == "admin"
