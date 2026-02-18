"""Phase 9 integration tests: enrichment flows through the full pipeline."""

from __future__ import annotations

import platform
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent.enrichment.process_identity import ProcessIdentity, clear_cache


@pytest.fixture(autouse=True)
def _clear_caches():
    clear_cache()
    yield
    clear_cache()


class TestEnrichmentPipeline:
    """Test that enrichment flows through entity extraction -> graph builder -> attack chain."""

    def test_enrichment_chain_process_activity(self):
        """Process identity should flow from extraction to attack chain serialization."""
        from agent.graph.queries import serialize_attack_chain
        from agent.processor.entity_extractor import extract_entities
        from agent.schema.ocsf_types import (
            DeviceInfo,
            ProcessActivity,
            ProcessInfo,
        )

        event = ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(
                pid=1234,
                name="curl",
                cmd_line="curl https://example.com",
                exe_path="/usr/bin/curl",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
        )

        entities = extract_entities(event, event_id=1)
        assert len(entities.processes) == 1
        proc = entities.processes[0]

        # Build a mock attack chain with identity from the process node
        chain = {
            "target_process": {
                "pid": proc.pid,
                "name": proc.name,
                "command_line": proc.cmd_line,
                "user": "test",
                "bundle_id": proc.bundle_id,
                "code_signed": proc.code_signed,
                "signing_authority": proc.signing_authority,
            },
            "process_chain": [],
            "network_footprint": {"domains": [], "ips": [], "dns_chains": []},
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
        }

        text = serialize_attack_chain(chain)
        assert "curl" in text
        if platform.system() == "Darwin":
            assert "signed=" in text

    def test_enrichment_chain_network_activity(self):
        """Network activity should get port mapper context."""
        from agent.enrichment.port_mapper import ListeningService, PortMapper
        from agent.processor.entity_extractor import extract_entities
        from agent.schema.ocsf_types import (
            DeviceInfo,
            NetworkActivity,
            NetworkEndpoint,
            ProcessInfo,
        )

        mapper = PortMapper(refresh_interval=0)
        mapper._port_map = {
            ("0.0.0.0", 62874): ListeningService(
                port=62874,
                protocol="tcp",
                pid=500,
                process_name="com.docker.backend",
                bind_address="0.0.0.0",
                identity=ProcessIdentity(
                    code_signed=True,
                    signing_authority="Docker Inc",
                ),
            ),
        }
        mapper._last_refresh = 1e18

        event = NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(
                pid=400,
                name="OrbStack Helper",
                cmd_line="orbhelper",
                exe_path="/Applications/OrbStack.app/Contents/Helpers/orbhelper",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
            dst_endpoint=NetworkEndpoint(ip="127.0.0.1", port=62874),
        )

        entities = extract_entities(event, event_id=1, port_mapper=mapper)

        # Should have a connection_context risk indicator
        ctx_indicators = [
            r for r in entities.risk_indicators
            if r.get("type") == "connection_context"
        ]
        assert len(ctx_indicators) == 1
        assert "Localhost IPC" in ctx_indicators[0]["description"]
        assert "com.docker.backend" in ctx_indicators[0]["description"]


class TestSerializeAttackChainEnrichment:
    """Test that serialize_attack_chain includes enrichment data."""

    def test_identity_in_target(self):
        from agent.graph.queries import serialize_attack_chain

        chain = {
            "target_process": {
                "pid": 400,
                "name": "OrbStack Helper",
                "command_line": "orbhelper",
                "user": "thomas",
                "bundle_id": "dev.kdrag0n.OrbStack",
                "code_signed": True,
                "signing_authority": "Developer ID Application: Khanh Dong Nguyen",
            },
            "process_chain": [],
            "network_footprint": {
                "domains": [],
                "ips": [{"address": "127.0.0.1", "port": 62874, "protocol": "TCP"}],
                "dns_chains": [],
                "listening_ports": [{"address": "0.0.0.0", "port": 62874, "protocol": "tcp"}],
            },
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
            "connection_context": [
                "Localhost IPC: OrbStack Helper -> com.docker.backend [both signed]",
            ],
        }

        text = serialize_attack_chain(chain)
        assert "OrbStack Helper" in text
        assert "bundle=dev.kdrag0n.OrbStack" in text
        assert "signed=" in text
        assert "Listening on:" in text
        assert "Connection context:" in text
        assert "Localhost IPC" in text


class TestAllowlistIntegration:
    """Test allowlist integration with the pipeline."""

    def test_allowlist_annotates_known_app(self):
        """Known apps should get allowlist annotations."""
        from agent.enrichment.application_allowlist import check_allowlist

        identity = ProcessIdentity(
            pid=100,
            name="OrbStack",
            bundle_id="dev.kdrag0n.OrbStack",
            code_signed=True,
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="127.0.0.1",
            dest_port=62874,
        )
        assert result.is_allowed is True
        assert result.confidence == "high"

    def test_allowlist_flags_unknown_app(self):
        """Unknown apps should not be in the allowlist."""
        from agent.enrichment.application_allowlist import check_allowlist

        identity = ProcessIdentity(
            pid=999,
            name="suspicious_process",
            bundle_id="com.evil.malware",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="10.10.10.10",
            dest_port=4444,
        )
        assert result.is_allowed is False


class TestConnectionMetadataStorage:
    """Test connection metadata SQLite operations."""

    def test_store_and_query(self, tmp_path):
        import sqlite3
        from agent.collectors.connection_metadata import (
            ConnectionMetadata,
            get_connection_metadata,
            init_connection_metadata_db,
            store_connection_metadata,
        )

        db_path = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        init_connection_metadata_db(conn)

        meta = ConnectionMetadata(
            source_pid=400,
            source_process="OrbStack",
            dest_ip="127.0.0.1",
            dest_port=62874,
            start_time=datetime.now(),
            tls_sni=None,
            is_encrypted=False,
        )
        store_connection_metadata(conn, meta)

        rows = get_connection_metadata(conn, pid=400, hours=1)
        assert len(rows) == 1
        assert rows[0]["dest_ip"] == "127.0.0.1"
        assert rows[0]["source_process"] == "OrbStack"
        conn.close()


class TestDashboardEndpoint:
    """Test dashboard connection metadata endpoint."""

    def test_connections_endpoint(self):
        """The /api/connections/{pid} endpoint should be registered."""
        from agent.dashboard.server import app

        # Check that the route exists
        routes = [r.path for r in app.routes]
        assert "/api/connections/{pid}" in routes


class TestConfigEnrichmentSettings:
    """Test that enrichment config settings exist."""

    def test_settings_have_enrichment_fields(self):
        from agent.config import Settings

        settings = Settings()
        assert settings.process_identity_enabled is True
        assert settings.process_identity_cache_size == 500
        assert settings.port_mapper_refresh_interval == 30.0
        assert settings.allowlist_enabled is True
        assert settings.allowlist_custom_entries == []
        assert settings.connection_metadata_enabled is True
        assert settings.connection_metadata_retention_hours == 24

    def test_yaml_key_map_has_enrichment_entries(self):
        from agent.config import _YAML_KEY_MAP

        enrichment_keys = [k for k in _YAML_KEY_MAP if k[0] == "enrichment"]
        assert len(enrichment_keys) >= 7
