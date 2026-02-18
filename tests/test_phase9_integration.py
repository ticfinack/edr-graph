"""Phase 9 integration tests: enrichment flows through the full pipeline.

Includes tests for:
- Commit 1: parent_pid storage, process chain walks, children, process tree, serialization
- Commit 2: ChainStep pid, affected_pids storage and querying
- Commit 3: Finding accumulation (update_finding, no duplicates)
"""

from __future__ import annotations

import json
import platform
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import kuzu
import pytest

from agent.enrichment.process_identity import ProcessIdentity, clear_cache
from agent.schema.graph_types import ChainStep, ProcessNode, SecurityFinding
from agent.schema.kuzu_schema import init_graph_schema
from agent.queue.sqlite_queue import SqliteQueue


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


# ── Helper factories ──────────────────────────────────────────────────


def _make_kuzu():
    """Create a temporary Kuzu database with schema initialized."""
    tmp_dir = tempfile.mkdtemp()
    db_path = tmp_dir + "/test_db"
    db = kuzu.Database(db_path)
    conn = kuzu.Connection(db)
    init_graph_schema(conn)
    return db, conn, tmp_dir


def _ts(s: str) -> str:
    return f"timestamp('{s}')"


def _make_queue() -> tuple[SqliteQueue, str]:
    tmp_dir = tempfile.mkdtemp()
    db_path = Path(tmp_dir) / "test_queue.db"
    queue = SqliteQueue(db_path)
    return queue, tmp_dir


# ── Commit 1: Process Tree Tests ─────────────────────────────────────


class TestParentPidStorage:
    def test_parent_pid_stored_and_queryable(self):
        """parent_pid is stored in graph and can be queried."""
        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'host:100:1000', name: 'bash', pid: 100, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'host', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 1}})"
            )
            result = conn.execute(
                "MATCH (p:Process {pid: 100}) RETURN p.parent_pid"
            )
            assert result.has_next()
            assert result.get_next()[0] == 1
        finally:
            shutil.rmtree(tmp_dir)

    def test_parent_pid_in_process_node_model(self):
        node = ProcessNode(
            id="host:1:1000", name="bash", pid=1,
            hostname="host", start_time=datetime.now(), parent_pid=42,
        )
        assert node.parent_pid == 42


class TestProcessChainWalk:
    def test_chain_walks_upward_through_parent_pid(self):
        from agent.graph.queries import get_process_chain

        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:1:1000', name: 'init', pid: 1, "
                "cmd_line: '/sbin/init', exe_path: '/sbin/init', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:2:1000', name: 'bash', pid: 2, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 1}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:3:1000', name: 'curl', pid: 3, "
                "cmd_line: 'curl evil.com', exe_path: '/usr/bin/curl', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:02:00')}, parent_pid: 2}})"
            )

            chain = get_process_chain(conn, 3)
            names = [p.get("name") for p in chain if p.get("name")]
            assert names == ["init", "bash", "curl"]
        finally:
            shutil.rmtree(tmp_dir)

    def test_chain_prepends_user(self):
        from agent.graph.queries import get_process_chain

        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (u:User {id: 'root', name: 'root', uid: '0', "
                f"first_seen: {_ts('2025-06-01 12:00:00')}, "
                f"last_seen: {_ts('2025-06-01 12:00:00')}}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:10:1000', name: 'zsh', pid: 10, "
                "cmd_line: '/bin/zsh', exe_path: '/bin/zsh', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "MATCH (u:User {id: 'root'}), (p:Process {id: 'h:10:1000'}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: {_ts('2025-06-01 12:00:00')}, "
                "activity_id: 1, event_id: 1}]->(p)"
            )
            chain = get_process_chain(conn, 10)
            assert chain[0].get("type") == "user"
            assert chain[0].get("name") == "root"
        finally:
            shutil.rmtree(tmp_dir)


class TestProcessChildren:
    def test_children_discovered_via_parent_pid(self):
        from agent.graph.queries import get_process_children

        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:1:1000', name: 'bash', pid: 1, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:10:1000', name: 'curl', pid: 10, "
                "cmd_line: 'curl evil.com', exe_path: '/usr/bin/curl', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 1}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:11:1000', name: 'wget', pid: 11, "
                "cmd_line: 'wget evil.com', exe_path: '/usr/bin/wget', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:02:00')}, parent_pid: 1}})"
            )
            children = get_process_children(conn, 1)
            assert len(children) == 2
            assert {c["name"] for c in children} == {"curl", "wget"}
        finally:
            shutil.rmtree(tmp_dir)


class TestProcessTree:
    def test_get_process_tree_returns_nested_structure(self):
        from agent.graph.queries import get_process_tree

        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:1:1000', name: 'bash', pid: 1, "
                "cmd_line: '/bin/bash', exe_path: '/bin/bash', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:2:1000', name: 'python', pid: 2, "
                "cmd_line: 'python script.py', exe_path: '/usr/bin/python', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 1}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:3:1000', name: 'curl', pid: 3, "
                "cmd_line: 'curl evil.com', exe_path: '/usr/bin/curl', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:02:00')}, parent_pid: 2}})"
            )
            tree = get_process_tree(conn, 2)
            assert tree is not None
            assert tree["target"]["name"] == "python"
            assert len(tree["ancestors"]) == 1
            assert tree["ancestors"][0]["name"] == "bash"
            assert len(tree["target"]["children"]) == 1
            assert tree["target"]["children"][0]["name"] == "curl"
        finally:
            shutil.rmtree(tmp_dir)

    def test_process_tree_nonexistent(self):
        from agent.graph.queries import get_process_tree

        db, conn, tmp_dir = _make_kuzu()
        try:
            assert get_process_tree(conn, 99999) is None
        finally:
            shutil.rmtree(tmp_dir)


class TestBuildAttackChainEnhanced:
    def test_attack_chain_includes_children(self):
        from agent.graph.queries import build_attack_chain

        db, conn, tmp_dir = _make_kuzu()
        try:
            conn.execute(
                "CREATE (p:Process {id: 'h:1:1000', name: 'zsh', pid: 1, "
                "cmd_line: '/bin/zsh', exe_path: '/bin/zsh', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:00:00')}, parent_pid: 0}})"
            )
            conn.execute(
                "CREATE (p:Process {id: 'h:2:1000', name: 'nslookup', pid: 2, "
                "cmd_line: 'nslookup evil.com', exe_path: '/usr/bin/nslookup', hostname: 'h', "
                f"start_time: {_ts('2025-06-01 12:01:00')}, parent_pid: 1}})"
            )
            chain = build_attack_chain(conn, 1)
            assert "child_processes" in chain
            assert len(chain["child_processes"]) == 1
            assert chain["child_processes"][0]["name"] == "nslookup"
        finally:
            shutil.rmtree(tmp_dir)


class TestSerializeAttackChainTree:
    def test_renders_tree_hierarchy(self):
        from agent.graph.queries import serialize_attack_chain

        chain = {
            "target_process": {
                "pid": 3, "name": "curl", "command_line": "curl evil.com", "user": "root",
            },
            "process_chain": [
                {"name": "init", "pid": 1, "cmd_line": "/sbin/init"},
                {"name": "bash", "pid": 2, "cmd_line": "/bin/bash"},
                {"name": "curl", "pid": 3, "cmd_line": "curl evil.com"},
            ],
            "child_processes": [],
            "network_footprint": {"domains": [], "ips": [], "dns_chains": [], "listening_ports": []},
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
        }
        text = serialize_attack_chain(chain)
        assert "Process tree:" in text
        assert "init (PID 1)" in text
        assert "bash (PID 2)" in text
        assert "curl (PID 3)" in text

    def test_renders_child_with_activity(self):
        from agent.graph.queries import serialize_attack_chain

        chain = {
            "target_process": {"pid": 1, "name": "zsh", "command_line": "/bin/zsh", "user": "root"},
            "process_chain": [{"name": "zsh", "pid": 1, "cmd_line": "/bin/zsh"}],
            "child_processes": [{
                "pid": 2, "name": "curl", "cmd_line": "curl evil.com",
                "code_signed": True, "signing_authority": "Apple",
                "network": [{"address": "1.2.3.4", "port": 443, "protocol": "TCP"}],
                "files": [{"file_path": "/tmp/payload", "operation": "CREATED"}],
                "children": [],
            }],
            "network_footprint": {"domains": [], "ips": [], "dns_chains": [], "listening_ports": []},
            "file_activity": [],
            "persistence_artifacts": [],
            "risk_indicators": [],
        }
        text = serialize_attack_chain(chain)
        assert "curl (PID 2)" in text
        assert "[signed=Apple]" in text
        assert "Network: -> 1.2.3.4:443" in text
        assert "File: CREATED /tmp/payload" in text


# ── Commit 2: PIDs in Findings Tests ─────────────────────────────────


class TestChainStepPid:
    def test_chain_step_includes_pid(self):
        step = ChainStep(entity_type="process", entity_id="h:100", entity_name="curl", pid=100)
        assert step.pid == 100
        assert step.model_dump(mode="json")["pid"] == 100

    def test_chain_step_pid_optional(self):
        step = ChainStep(entity_type="user", entity_id="root", entity_name="root")
        assert step.pid is None


class TestAffectedPids:
    def test_affected_pids_stored_and_queryable(self):
        queue, tmp_dir = _make_queue()
        try:
            finding = SecurityFinding(
                id="test-f-1", timestamp=datetime.now(), severity="high",
                title="Suspicious curl", description="payload download",
                affected_entities=["curl"], evidence_event_ids=[1, 2],
                recommendation="Investigate", chain=[], affected_pids=[100, 200],
            )
            queue.store_finding(finding)

            assert len(queue.get_findings_for_pids([100])) == 1
            assert len(queue.get_findings_for_pids([999])) == 0
            assert queue.get_findings_for_pids([100])[0].affected_pids == [100, 200]
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)


class TestUpdateFinding:
    def test_update_merges_evidence_ids(self):
        queue, tmp_dir = _make_queue()
        try:
            finding = SecurityFinding(
                id="upd-1", timestamp=datetime.now(), severity="medium",
                title="Test", description="Initial", affected_entities=["curl"],
                evidence_event_ids=[1, 2, 3], recommendation="Investigate",
                chain=[], affected_pids=[100],
            )
            queue.store_finding(finding)
            assert queue.update_finding("upd-1", new_evidence_ids=[3, 4, 5],
                                        new_description="Updated", new_severity="high")

            updated = [f for f in queue.get_findings() if f.id == "upd-1"][0]
            assert updated.evidence_event_ids == [1, 2, 3, 4, 5]
            assert updated.description == "Updated"
            assert updated.severity == "high"
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)

    def test_update_never_downgrades_severity(self):
        queue, tmp_dir = _make_queue()
        try:
            finding = SecurityFinding(
                id="sev-1", timestamp=datetime.now(), severity="high",
                title="Test", description="Test", affected_entities=[],
                evidence_event_ids=[1], recommendation="", chain=[], affected_pids=[],
            )
            queue.store_finding(finding)
            queue.update_finding("sev-1", new_severity="low")

            updated = [f for f in queue.get_findings() if f.id == "sev-1"][0]
            assert updated.severity == "high"
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)

    def test_update_nonexistent_returns_false(self):
        queue, tmp_dir = _make_queue()
        try:
            assert queue.update_finding("nope", new_evidence_ids=[1]) is False
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)


# ── Commit 3: Finding Accumulation Tests ─────────────────────────────


class TestFindingAccumulation:
    def test_existing_findings_for_batch_pids(self):
        queue, tmp_dir = _make_queue()
        try:
            f1 = SecurityFinding(
                id="f-pid-100", timestamp=datetime.now(), severity="medium",
                title="DNS anomaly", description="Suspicious DNS",
                affected_entities=["nslookup"], evidence_event_ids=[10],
                recommendation="Review", chain=[], affected_pids=[100],
            )
            f2 = SecurityFinding(
                id="f-pid-200", timestamp=datetime.now(), severity="low",
                title="File download", description="File downloaded",
                affected_entities=["curl"], evidence_event_ids=[20],
                recommendation="Review", chain=[], affected_pids=[200],
            )
            queue.store_finding(f1)
            queue.store_finding(f2)

            assert len(queue.get_findings_for_pids([100])) == 1
            assert len(queue.get_findings_for_pids([100, 200])) == 2
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)

    def test_accumulation_no_duplicates(self):
        """Repeated updates to same finding accumulate evidence, not create duplicates."""
        queue, tmp_dir = _make_queue()
        try:
            finding = SecurityFinding(
                id="accum-1", timestamp=datetime.now(), severity="medium",
                title="Ongoing activity", description="Batch 1: DNS",
                affected_entities=["curl"], evidence_event_ids=[1, 2],
                recommendation="Monitor", chain=[], affected_pids=[100],
            )
            queue.store_finding(finding)

            queue.update_finding("accum-1", new_evidence_ids=[3, 4],
                                 new_description="Batch 2: File download", new_severity="high")
            queue.update_finding("accum-1", new_evidence_ids=[5, 6],
                                 new_description="Batch 3: Payload", new_severity="critical")

            all_f = queue.get_findings(limit=100)
            matching = [f for f in all_f if f.id == "accum-1"]
            assert len(matching) == 1
            assert matching[0].evidence_event_ids == [1, 2, 3, 4, 5, 6]
            assert matching[0].severity == "critical"
        finally:
            queue.close()
            shutil.rmtree(tmp_dir)


class TestProcessByNameEndpoint:
    def test_endpoint_registered(self):
        from agent.dashboard.server import app

        routes = [r.path for r in app.routes]
        assert "/api/graph/process-by-name/{name}" in routes
