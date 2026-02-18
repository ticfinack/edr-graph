"""Tests for the analyzer (preflight and LLM parsing)."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.config import Settings
from agent.schema.ocsf_types import (
    ActorInfo,
    Authentication,
    DeviceInfo,
    NetworkActivity,
    NetworkEndpoint,
    ProcessActivity,
    ProcessInfo,
    UserInfo,
)


class TestParseFindings:
    def setup_method(self):
        self.settings = Settings(deepinfra_api_key="test-key")
        # Mock kuzu.Database
        self.mock_db = MagicMock()
        self.analyzer = LlmAnalyzer(self.settings, self.mock_db)

    def test_parse_valid_findings(self):
        content = json.dumps([
            {
                "severity": "high",
                "title": "Suspicious curl execution",
                "description": "User alice ran curl to unknown IP",
                "affected_entities": ["alice", "curl"],
                "evidence_event_ids": [1],
                "recommendation": "Investigate",
                "chain": [
                    {"entity_type": "user", "entity_id": "alice", "entity_name": "alice"},
                    {"entity_type": "process", "entity_id": "curl", "entity_name": "curl"},
                    {"entity_type": "ip", "entity_id": "1.2.3.4", "entity_name": "1.2.3.4"},
                ],
            }
        ])
        events = [
            (1, ProcessActivity(
                activity_id=1, severity_id=1, time=datetime.now(),
                process=ProcessInfo(pid=1, name="curl"),
                device=DeviceInfo(hostname="test"),
            ))
        ]
        findings = self.analyzer._parse_findings(content, events)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].title == "Suspicious curl execution"
        assert len(findings[0].chain) == 3

    def test_parse_empty_array(self):
        events = []
        findings = self.analyzer._parse_findings("[]", events)
        assert findings == []

    def test_parse_markdown_fenced_json(self):
        content = "```json\n[]\n```"
        findings = self.analyzer._parse_findings(content, [])
        assert findings == []

    def test_parse_invalid_json(self):
        findings = self.analyzer._parse_findings("not json at all", [])
        assert findings == []


class TestBatchContext:
    def setup_method(self):
        self.settings = Settings(deepinfra_api_key="test-key")
        self.mock_db = MagicMock()
        self.analyzer = LlmAnalyzer(self.settings, self.mock_db)

    def test_build_process_context(self):
        events = [
            (1, ProcessActivity(
                activity_id=1, severity_id=1,
                time=datetime(2025, 1, 15, 10, 0),
                actor=ActorInfo(user=UserInfo(name="alice")),
                process=ProcessInfo(pid=1234, name="curl", cmd_line="curl https://evil.com"),
                device=DeviceInfo(hostname="test"),
            ))
        ]
        # Mock the kuzu Connection to avoid actual DB
        with patch("agent.analyzer.llm_analyzer.kuzu") as mock_kuzu:
            mock_conn = MagicMock()
            mock_result = MagicMock()
            mock_result.has_next.return_value = False
            mock_conn.execute.return_value = mock_result
            mock_kuzu.Connection.return_value = mock_conn

            context = self.analyzer._build_batch_context(events)

        assert "curl" in context
        assert "alice" in context
        assert "Event 1" in context

    def test_build_network_context(self):
        events = [
            (2, NetworkActivity(
                activity_id=1, severity_id=1,
                time=datetime(2025, 1, 15, 10, 0),
                process=ProcessInfo(pid=1, name="wget"),
                dst_endpoint=NetworkEndpoint(ip="1.2.3.4", port=443),
                device=DeviceInfo(hostname="test"),
            ))
        ]
        with patch("agent.analyzer.llm_analyzer.kuzu") as mock_kuzu:
            mock_conn = MagicMock()
            mock_result = MagicMock()
            mock_result.has_next.return_value = False
            mock_conn.execute.return_value = mock_result
            mock_kuzu.Connection.return_value = mock_conn

            context = self.analyzer._build_batch_context(events)

        assert "wget" in context
        assert "1.2.3.4" in context
