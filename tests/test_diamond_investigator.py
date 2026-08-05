"""Tests for Diamond Model Investigator, campaign grouping, OCSF evidence,
and dashboard API endpoints.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock
from urllib.parse import urlparse

import pytest

from server.settings_db import SettingsDB

# ── Fixtures ──


@pytest.fixture
def db(tmp_path):
    sdb = SettingsDB(tmp_path / "settings.db")
    yield sdb
    sdb.close()


def _make_neo4j_client():
    from server.neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client._driver = MagicMock()
    return client


def _mock_session(client):
    mock_session = MagicMock()
    client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    client._driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return mock_session


# ── OCSF Evidence CRUD Tests ──


class TestOcsfEvidence:
    def test_tables_created(self, db):
        conn = db._conn()
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        assert "incident_ocsf_evidence" in tables
        assert "incident_diamond_assessments" in tables

    def test_upsert_and_get(self, db):
        records = [
            {"id": 1, "timestamp": 1700000001.0, "event_type": "ProcessActivity", "ocsf_json": '{"class_uid":1001}'},
            {"id": 2, "timestamp": 1700000002.0, "event_type": "NetworkActivity", "ocsf_json": '{"class_uid":4001}'},
        ]
        inserted = db.upsert_ocsf_evidence("inc-001", "agent-a", records)
        assert inserted == 2

        evidence = db.get_ocsf_evidence("inc-001")
        assert len(evidence) == 2
        assert evidence[0]["timestamp"] > evidence[1]["timestamp"]  # DESC order
        assert evidence[0]["event_type"] == "NetworkActivity"
        assert evidence[1]["ocsf_json"] == '{"class_uid":1001}'

    def test_dedup_on_upsert(self, db):
        records = [{"id": 1, "timestamp": 1700000001.0, "event_type": "ProcessActivity", "ocsf_json": "{}"}]
        db.upsert_ocsf_evidence("inc-001", "agent-a", records)
        inserted = db.upsert_ocsf_evidence("inc-001", "agent-a", records)
        assert inserted == 0  # No new rows
        assert len(db.get_ocsf_evidence("inc-001")) == 1

    def test_different_agents_not_deduped(self, db):
        records = [{"id": 1, "timestamp": 1700000001.0, "event_type": "ProcessActivity", "ocsf_json": "{}"}]
        db.upsert_ocsf_evidence("inc-001", "agent-a", records)
        inserted = db.upsert_ocsf_evidence("inc-001", "agent-b", records)
        assert inserted == 1
        assert len(db.get_ocsf_evidence("inc-001")) == 2

    def test_get_with_limit(self, db):
        records = [{"id": i, "timestamp": 1700000000 + i, "event_type": "Process", "ocsf_json": "{}"} for i in range(10)]
        db.upsert_ocsf_evidence("inc-001", "agent-a", records)
        assert len(db.get_ocsf_evidence("inc-001", limit=5)) == 5

    def test_empty_incident(self, db):
        assert db.get_ocsf_evidence("nonexistent") == []


# ── Diamond Assessment CRUD Tests ──


class TestDiamondAssessment:
    def test_save_and_get(self, db):
        assessment = {"assessment_verdict": "suspicious", "confidence": 0.8}
        db.save_diamond_assessment("inc-001", json.dumps(assessment), "gemma-3-27b", 500, 200)

        latest = db.get_latest_diamond_assessment("inc-001")
        assert latest is not None
        assert latest["model_name"] == "gemma-3-27b"
        assert latest["prompt_tokens"] == 500
        assert latest["completion_tokens"] == 200
        parsed = json.loads(latest["assessment_json"])
        assert parsed["assessment_verdict"] == "suspicious"
        assert latest["assessed_at"] > 0

    def test_latest_returns_most_recent(self, db):
        # Insert directly with controlled timestamps to avoid int(time.time()) granularity
        conn = db._conn()
        conn.execute(
            "INSERT INTO incident_diamond_assessments "
            "(incident_id, assessment_json, model_name, prompt_tokens, completion_tokens, assessed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("inc-001", '{"v":1}', "model-a", 100, 50, 1000),
        )
        conn.execute(
            "INSERT INTO incident_diamond_assessments "
            "(incident_id, assessment_json, model_name, prompt_tokens, completion_tokens, assessed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("inc-001", '{"v":2}', "model-b", 200, 100, 2000),
        )
        conn.commit()

        latest = db.get_latest_diamond_assessment("inc-001")
        parsed = json.loads(latest["assessment_json"])
        assert parsed["v"] == 2
        assert latest["model_name"] == "model-b"

    def test_no_assessment_returns_none(self, db):
        assert db.get_latest_diamond_assessment("nonexistent") is None


# ── Diamond Investigator Context Building & Parsing ──


class TestDiamondParsing:
    def test_parse_clean_json(self):
        from server.analyzer.diamond_investigator import _parse_assessment

        content = '{"assessment_verdict":"malicious","confidence":0.9}'
        result = _parse_assessment(content)
        assert result["assessment_verdict"] == "malicious"
        assert result["confidence"] == 0.9

    def test_parse_json_in_code_fence(self):
        from server.analyzer.diamond_investigator import _parse_assessment

        content = '```json\n{"assessment_verdict":"benign","confidence":0.1}\n```'
        result = _parse_assessment(content)
        assert result["assessment_verdict"] == "benign"

    def test_parse_json_with_surrounding_text(self):
        from server.analyzer.diamond_investigator import _parse_assessment

        content = 'Here is my analysis:\n{"assessment_verdict":"suspicious","confidence":0.5}\nThat is all.'
        result = _parse_assessment(content)
        assert result["assessment_verdict"] == "suspicious"

    def test_parse_empty_returns_none(self):
        from server.analyzer.diamond_investigator import _parse_assessment

        assert _parse_assessment("") is None
        assert _parse_assessment(None) is None

    def test_parse_invalid_json_returns_none(self):
        from server.analyzer.diamond_investigator import _parse_assessment

        assert _parse_assessment("not json at all") is None


class TestDiamondContextBuilding:
    def test_build_context_with_evidence(self):
        from server.analyzer.diamond_investigator import DiamondInvestigator

        di = DiamondInvestigator.__new__(DiamondInvestigator)
        detail = {
            "incident_id": "inc-001",
            "incident_type": "lateral_movement",
            "status": "active",
            "src_hostname": "host-a",
            "src_agent_id": "agent-a",
            "dst_hostname": "host-b",
            "dst_agent_id": "agent-b",
            "pivot_ip": "10.0.0.5",
            "involved_hosts": [
                {"hostname": "host-a", "agent_id": "agent-a"},
                {"hostname": "host-b", "agent_id": "agent-b"},
            ],
            "source_findings": [{"severity": "high", "title": "SSH Brute Force", "hostname": "host-a", "timestamp": 1700000000}],
            "source_chain": [
                {"step_index": 0, "entity_type": "user", "entity_name": "attacker", "pid": 0},
                {"step_index": 1, "entity_type": "process", "entity_name": "ssh", "pid": 1234},
            ],
            "target_chain": [],
            "follow_on_findings": [],
        }
        evidence = [
            {"event_type": "ProcessActivity", "timestamp": 1700000001, "ocsf_json": '{"class_uid":1001}'},
            {"event_type": "NetworkActivity", "timestamp": 1700000002, "ocsf_json": '{"class_uid":4001}'},
        ]

        ctx = di._build_context(detail, evidence)
        assert "inc-001" in ctx
        assert "host-a" in ctx
        assert "SSH Brute Force" in ctx
        assert "OCSF Telemetry Evidence" in ctx
        assert len(ctx) <= 45000  # within limit

    def test_build_context_respects_char_limit(self):
        from server.analyzer.diamond_investigator import DiamondInvestigator

        di = DiamondInvestigator.__new__(DiamondInvestigator)
        detail = {
            "incident_id": "inc-001",
            "incident_type": "campaign",
            "status": "active",
            "src_hostname": "h", "src_agent_id": "a",
            "dst_hostname": "h2", "dst_agent_id": "b",
            "pivot_ip": "10.0.0.1",
            "involved_hosts": [],
            "source_findings": [],
            "source_chain": [], "target_chain": [],
            "follow_on_findings": [],
        }
        # Create lots of large evidence
        evidence = [
            {"event_type": "ProcessActivity", "timestamp": i, "ocsf_json": "x" * 2000}
            for i in range(100)
        ]

        ctx = di._build_context(detail, evidence)
        assert len(ctx) <= 45000


# ── Campaign Grouping Tests ──


class TestCampaignGrouping:
    def test_find_active_campaign(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        record = MagicMock()
        record.__getitem__ = lambda self, k: "inc-existing"
        session.run.return_value.single.return_value = record

        result = client.find_active_campaign(["agent-a", "agent-b"], ["10.0.0.5"])
        assert result == "inc-existing"

    def test_find_active_campaign_none(self):
        client = _make_neo4j_client()
        session = _mock_session(client)
        session.run.return_value.single.return_value = None

        result = client.find_active_campaign(["agent-a"], ["10.0.0.5"])
        assert result is None

    def test_append_finding_to_incident(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        # Should not raise
        client.append_finding_to_incident("inc-001", "f-002", "agent-a", "agent-b", "10.0.0.5")
        assert session.run.call_count >= 3  # Link finding + INVOLVES_HOST(s) + PIVOT_VIA + campaign upgrade

    def test_append_finding_no_pivot_ip(self):
        """Vertical movement: pivot_ip is empty, should skip PIVOT_VIA."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        client.append_finding_to_incident("inc-001", "f-002", "agent-a", "agent-a", "")
        # Gather all query strings to verify PIVOT_VIA was skipped
        queries = [str(call) for call in session.run.call_args_list]
        pivot_calls = [q for q in queries if "PIVOT_VIA" in q]
        assert len(pivot_calls) == 0

    def test_check_finding_for_vertical_movement(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        session.run.return_value = [
            {"agent_id": "agent-a", "hostname": "host-a", "original_user": "user1", "escalated_user": "root"},
        ]

        result = client.check_finding_for_vertical_movement("agent-a", "f-001")
        assert len(result) == 1
        assert result[0]["escalated_user"] == "root"

    def test_get_incident_involved_agents(self):
        client = _make_neo4j_client()
        session = _mock_session(client)

        session.run.return_value = [
            {"agent_id": "agent-a"},
            {"agent_id": "agent-b"},
        ]

        result = client.get_incident_involved_agents("inc-001")
        assert result == ["agent-a", "agent-b"]


# ── gRPC OCSF Ingestion Tests ──


class TestGrpcOcsfIngestion:
    def test_ingest_ocsf_evidence(self, db):
        from server.grpc_service import FleetServicer

        client = _make_neo4j_client()
        svc = FleetServicer(client, settings_db=db)

        query_meta = {
            "finding_id": "inc-001:ocsf_dst",
            "agent_id": "agent-b",
            "query_type": "pull_ocsf_ledger",
        }
        result = {
            "records": [
                {"id": 1, "timestamp": 1700000001, "event_type": "ProcessActivity", "ocsf_json": '{"class_uid":1001}'},
                {"id": 2, "timestamp": 1700000002, "event_type": "NetworkActivity", "ocsf_json": '{"class_uid":4001}'},
            ]
        }

        svc._ingest_ocsf_evidence(query_meta, result)

        evidence = db.get_ocsf_evidence("inc-001")
        assert len(evidence) == 2

    def test_ingest_ocsf_no_incident_id(self, db):
        from server.grpc_service import FleetServicer

        client = _make_neo4j_client()
        svc = FleetServicer(client, settings_db=db)

        # finding_id without :ocsf_ prefix → should be ignored
        svc._ingest_ocsf_evidence({"finding_id": "something-else", "agent_id": "a"}, {"records": [{"id": 1}]})
        assert db.get_ocsf_evidence("something-else") == []

    def test_ingest_ocsf_empty_records(self, db):
        from server.grpc_service import FleetServicer

        client = _make_neo4j_client()
        svc = FleetServicer(client, settings_db=db)

        svc._ingest_ocsf_evidence({"finding_id": "inc-001:ocsf_src", "agent_id": "a"}, {"records": []})
        assert db.get_ocsf_evidence("inc-001") == []


# ── Federated Query Handler Tests ──


class TestPullOcsfLedger:
    def test_handler_registered(self):
        from agent.graph.federated_queries import _HANDLERS

        assert "pull_ocsf_ledger" in _HANDLERS

    def test_handler_no_ledger_returns_error(self):
        from agent.graph.federated_queries import pull_ocsf_ledger

        result = pull_ocsf_ledger(None, {"ips": ["10.0.0.1"]})
        assert result["status"] == "error"


# ── Config Tests ──


class TestServerConfig:
    def test_deepinfra_fields_exist(self):
        from server.config import ServerSettings

        s = ServerSettings()
        assert hasattr(s, "deepinfra_api_key")
        assert hasattr(s, "deepinfra_base_url")
        assert hasattr(s, "deepinfra_model")
        # Compare the parsed host rather than doing a substring match: a
        # substring test would also accept hosts like "deepinfra.com.evil.tld"
        # or "http://evil.tld/?x=deepinfra.com" (CodeQL py/incomplete-url-
        # substring-sanitization).
        host = urlparse(s.deepinfra_base_url).hostname or ""
        assert host == "deepinfra.com" or host.endswith(".deepinfra.com")
        assert "gemma" in s.deepinfra_model


# ── Incident Detail Enrichment ──


class TestIncidentDetailEnrichment:
    def test_get_incident_detail_includes_new_fields(self):
        """get_incident_detail returns diamond assessment and source findings."""
        client = _make_neo4j_client()
        session = _mock_session(client)

        # Use a dict-like object that works with dict() conversion
        base_data = {
            "incident_id": "inc-001",
            "incident_type": "lateral_movement",
            "status": "active",
            "src_agent_id": "a",
            "src_hostname": "h1",
            "dst_agent_id": "b",
            "dst_hostname": "h2",
            "pivot_ip": "10.0.0.5",
            "created_at": 1700000000,
            "updated_at": 1700000100,
            "diamond_assessment_json": None,
            "diamond_assessed_at": None,
        }

        class DictRecord:
            def __init__(self, d):
                self._d = d
            def __getitem__(self, k):
                return self._d[k]
            def keys(self):
                return self._d.keys()

        call_count = [0]

        def mock_run(query, params=None):
            call_count[0] += 1
            result = MagicMock()
            if call_count[0] == 1:
                result.single.return_value = DictRecord(base_data)
            else:
                result.__iter__ = MagicMock(return_value=iter([]))
            return result

        session.run.side_effect = mock_run

        detail = client.get_incident_detail("inc-001")
        assert detail is not None
        assert "source_findings" in detail
        assert "involved_hosts" in detail
        assert "diamond_assessment_json" in detail
        assert "finding_chains" in detail
        assert isinstance(detail["finding_chains"], list)
