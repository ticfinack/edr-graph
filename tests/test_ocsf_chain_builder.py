"""Tests for OCSF synthetic chain builder and Phase 2B fallback wiring.

Covers:
- _build_chain_from_ocsf_evidence: building target chains from raw OCSF
  ledger evidence (Authentication, NetworkActivity, ProcessActivity)
- Temporal guardrails preventing PID-reuse collisions
- Integration with get_lateral_movement_detail Phase 2B fallback
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from server.neo4j_client import _build_chain_from_ocsf_evidence

# ── Helpers ──────────────────────────────────────────────────────────


def _ocsf_row(
    agent_id: str,
    event_type: str,
    timestamp: float,
    ocsf: dict,
) -> dict:
    """Build a minimal incident_ocsf_evidence row."""
    return {
        "agent_id": agent_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "ocsf_json": json.dumps(ocsf),
    }


TARGET = "agent-target"
PIVOT_IP = "10.0.0.1"


def _auth_event(pid: int, user: str, ts: float) -> dict:
    """OCSF Authentication event payload."""
    return {
        "src_endpoint": {"ip": PIVOT_IP},
        "process": {"pid": pid, "name": "sshd", "cmd_line": "/usr/sbin/sshd"},
        "user": {"name": user},
    }


def _net_event(pid: int, ts: float) -> dict:
    """OCSF NetworkActivity event payload."""
    return {
        "src_endpoint": {"ip": PIVOT_IP},
        "process": {"pid": pid, "name": "sshd", "cmd_line": "/usr/sbin/sshd"},
    }


def _proc_event(pid: int, ppid: int, name: str, cmd: str, user: str = "") -> dict:
    """OCSF ProcessActivity event payload."""
    evt: dict = {
        "process": {"pid": pid, "parent_pid": ppid, "name": name, "cmd_line": cmd},
    }
    if user:
        evt["actor"] = {"user": {"name": user}}
    return evt


# ── Unit tests for _build_chain_from_ocsf_evidence ──────────────────


class TestBuildChainFromOcsfEvidence:

    def test_builds_chain_from_auth_and_process(self):
        """Auth event + ProcessActivity child → IP → sshd → user → bash."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash", "root")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        types = [s["entity_type"] for s in chain]
        assert types == ["ip", "process", "user", "process"]
        assert chain[0]["entity_id"] == PIVOT_IP
        assert chain[1]["entity_name"] == "sshd"
        assert chain[2]["entity_name"] == "root"
        assert chain[3]["entity_name"] == "bash"

    def test_filters_by_target_agent_id(self):
        """Events from wrong agent_id are ignored."""
        rows = [
            _ocsf_row("agent-other", "Authentication", 1000, _auth_event(100, "root", 1000)),
            _ocsf_row("agent-other", "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash")),
        ]
        result = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert result is None

    def test_returns_none_without_pivot_match(self):
        """No src_endpoint.ip matching pivot → returns None."""
        ocsf = {
            "src_endpoint": {"ip": "192.168.99.99"},
            "process": {"pid": 100, "name": "sshd"},
            "user": {"name": "root"},
        }
        rows = [_ocsf_row(TARGET, "Authentication", 1000, ocsf)]
        result = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert result is None

    def test_returns_none_for_empty_rows(self):
        """Empty input → returns None."""
        assert _build_chain_from_ocsf_evidence([], TARGET, [PIVOT_IP]) is None
        assert _build_chain_from_ocsf_evidence(None, TARGET, [PIVOT_IP]) is None

    def test_returns_none_for_empty_pivots(self):
        """Empty pivot_ips → returns None."""
        rows = [_ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000))]
        assert _build_chain_from_ocsf_evidence(rows, TARGET, []) is None

    def test_walks_multi_level_children(self):
        """sshd(100) → bash(200) → curl(300): grandchild included."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash", "root")),
            _ocsf_row(TARGET, "ProcessActivity", 1002, _proc_event(300, 200, "curl", "curl http://evil.com")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        names = [s["entity_name"] for s in chain if s["entity_type"] == "process"]
        assert names == ["sshd", "bash", "curl"]

    def test_network_activity_anchor(self):
        """NetworkActivity (not Auth) as anchor event still produces chain."""
        rows = [
            _ocsf_row(TARGET, "NetworkActivity", 1000, _net_event(100, 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash", "admin")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        types = [s["entity_type"] for s in chain]
        # IP → sshd → bash → user (user from ProcessActivity actor)
        assert "ip" in types
        assert "process" in types
        assert "user" in types

    def test_step_index_assigned(self):
        """All steps have sequential step_index."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash", "root")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        indexes = [s["step_index"] for s in chain]
        assert indexes == list(range(len(chain)))

    def test_user_inserted_after_authenticating_process(self):
        """User step placed after the first process with matching username (sshd)."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "deploy", 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1001, _proc_event(200, 100, "bash", "-bash", "deploy")),
            _ocsf_row(TARGET, "ProcessActivity", 1002, _proc_event(300, 200, "make", "make install")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        # Find user step
        user_steps = [s for s in chain if s["entity_type"] == "user"]
        assert len(user_steps) == 1
        assert user_steps[0]["entity_name"] == "deploy"
        # User should appear after sshd (the authenticating process with username=deploy)
        sshd_idx = next(s["step_index"] for s in chain if s["entity_name"] == "sshd")
        assert user_steps[0]["step_index"] == sshd_idx + 1

    def test_temporal_guardrail_rejects_stale_child(self):
        """Child process with timestamp before anchor is rejected."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000)),
            # This ProcessActivity has timestamp 500 — BEFORE the anchor at 1000
            _ocsf_row(TARGET, "ProcessActivity", 500, _proc_event(200, 100, "bash", "-bash")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        # Should still produce a chain (anchor process) but bash should NOT be included
        assert chain is not None
        names = [s["entity_name"] for s in chain if s["entity_type"] == "process"]
        assert "bash" not in names

    def test_temporal_guardrail_rejects_child_before_parent(self):
        """Child timestamp < parent timestamp → rejected."""
        rows = [
            _ocsf_row(TARGET, "Authentication", 1000, _auth_event(100, "root", 1000)),
            _ocsf_row(TARGET, "ProcessActivity", 1005, _proc_event(200, 100, "bash", "-bash")),
            # curl at ts=1003 — after anchor (1000) but before parent bash (1005)
            _ocsf_row(TARGET, "ProcessActivity", 1003, _proc_event(300, 200, "curl", "curl evil")),
        ]
        chain = _build_chain_from_ocsf_evidence(rows, TARGET, [PIVOT_IP])
        assert chain is not None
        names = [s["entity_name"] for s in chain if s["entity_type"] == "process"]
        assert "bash" in names
        assert "curl" not in names


# ── Integration test for Phase 2B wiring ─────────────────────────────


class TestOcsfFallbackInLateralDetail:

    def test_ocsf_fallback_in_lateral_detail(self):
        """Phase 2B: XDR empty + OCSF rows → target_chain populated."""
        from server.neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client._driver = MagicMock()

        mock_session = MagicMock()
        client._driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        client._driver.session.return_value.__exit__ = MagicMock(return_value=False)

        # Phase 1 query returns basic lateral data
        phase1_record = {
            "src_agent_id": "agent-src",
            "src_hostname": "src-host",
            "src_ip_addresses": ["10.0.0.1"],
            "finding_id": "f-001",
            "title": "SSH lateral",
            "severity": "high",
            "timestamp": 1000,
            "description": "lateral movement",
            "source_chain": [{"entity_type": "user", "entity_id": "admin", "step_index": 0}],
            "pivot_ip": "10.0.0.1",
            "dst_agent_id": "agent-target",
            "dst_hostname": "target-host",
        }

        # Phase 2A returns empty target chain
        phase2a_record = {"target_chain": []}

        # _get_incident_id_for_finding returns incident
        incident_record = MagicMock()
        incident_record.__getitem__ = lambda self, key: "inc-001" if key == "incident_id" else None

        # XDR result completed but empty records
        xdr_completed = {"status": "completed", "result_json": json.dumps({"records": []})}

        # Configure session.run to return different results for different queries
        # Flow: Phase 0 → Phase 1 → Phase 2A → [2B: incident lookup] → [persist]
        def session_run_side_effect(query, params=None):
            result = MagicMock()
            if "HAS_TARGET_CHAIN" in query and "HAS_SOURCE_CHAIN" in query:
                # Phase 0 — return None to skip persisted chains
                result.single.return_value = None
                return result
            if "SOURCE_FINDING" in query:
                # _get_incident_id_for_finding
                result.single.return_value = incident_record
                return result
            if "initiator" in query:
                # Phase 1
                result.single.return_value = phase1_record
                return result
            if "dst_agent_id" in str(params or {}):
                # Phase 2A
                result.single.return_value = phase2a_record
                return result
            # Persist calls (MERGE queries)
            result.single.return_value = None
            return result

        mock_session.run.side_effect = session_run_side_effect

        # Mock settings_db with OCSF evidence
        settings_db = MagicMock()
        settings_db.get_xdr_result.return_value = xdr_completed

        ocsf_rows = [
            _ocsf_row("agent-target", "Authentication", 1000,
                       _auth_event(100, "root", 1000)),
            _ocsf_row("agent-target", "ProcessActivity", 1001,
                       _proc_event(200, 100, "bash", "-bash", "root")),
        ]
        settings_db.get_ocsf_evidence.return_value = ocsf_rows

        result = client.get_lateral_movement_detail("f-001", settings_db=settings_db)

        assert result.get("target_chain_ocsf_synthetic") is True
        assert len(result.get("target_chain", [])) > 1
        # Chain should have IP, process(es), user
        types = [s["entity_type"] for s in result["target_chain"]]
        assert "ip" in types
        assert "process" in types
