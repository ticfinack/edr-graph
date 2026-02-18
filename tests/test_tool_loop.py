"""Tests for the LLM tool-use loop in llm_analyzer.py."""

import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent.analyzer.llm_analyzer import LlmAnalyzer
from agent.config import Settings
from agent.schema.ocsf_types import (
    DeviceInfo,
    NetworkActivity,
    NetworkEndpoint,
    ProcessActivity,
    ProcessInfo,
)


def _make_events():
    """Helper: create a small batch of test events."""
    return [
        (1, ProcessActivity(
            activity_id=1, severity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=100, name="curl", cmd_line="curl https://evil.com"),
            device=DeviceInfo(hostname="test-host"),
        )),
        (2, NetworkActivity(
            activity_id=1, severity_id=1,
            time=datetime(2025, 6, 1, 12, 1),
            process=ProcessInfo(pid=100, name="curl"),
            dst_endpoint=NetworkEndpoint(ip="93.184.216.34", port=443),
            device=DeviceInfo(hostname="test-host"),
        )),
    ]


def _mock_choice(content, finish_reason="stop", tool_calls=None):
    """Build a mock OpenAI ChatCompletion choice."""
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(
        finish_reason=finish_reason,
        message=message,
    )])


def _mock_tool_call(tc_id, name, arguments):
    """Build a mock tool_call object."""
    return SimpleNamespace(
        id=tc_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _patch_kuzu():
    """Patch kuzu so Connection().execute().has_next() returns False."""
    patcher = patch("agent.analyzer.llm_analyzer.kuzu")
    mock_kuzu = patcher.start()
    mock_conn = MagicMock()
    mock_result = MagicMock()
    mock_result.has_next.return_value = False
    mock_conn.execute.return_value = mock_result
    mock_kuzu.Connection.return_value = mock_conn
    return patcher


class TestToolLoop:
    def setup_method(self):
        self.settings = Settings(
            deepinfra_api_key="test-key",
            tool_use_enabled=True,
        )
        self.mock_db = MagicMock()

    def _make_analyzer(self):
        patcher = _patch_kuzu()
        try:
            return LlmAnalyzer(self.settings, self.mock_db)
        finally:
            patcher.stop()

    def test_no_tool_calls_single_pass(self):
        """LLM returns stop immediately → single pass, no tool use."""
        analyzer = self._make_analyzer()
        events = _make_events()

        mock_response = _mock_choice("[]", finish_reason="stop")
        analyzer._client = MagicMock()
        analyzer._client.chat.completions.create.return_value = mock_response

        patcher = _patch_kuzu()
        try:
            findings = analyzer.analyze_batch(events)
        finally:
            patcher.stop()

        assert findings == []
        # Only one LLM call
        assert analyzer._client.chat.completions.create.call_count == 1

    def test_one_round_of_tool_calls(self):
        """LLM makes tool calls in first round, then returns findings."""
        analyzer = self._make_analyzer()
        events = _make_events()

        # First call: LLM requests ip_geolocation
        tool_call = _mock_tool_call("tc_1", "ip_geolocation", {"ip": "93.184.216.34"})
        first_response = _mock_choice(
            None, finish_reason="tool_calls", tool_calls=[tool_call]
        )

        # Second call: LLM returns findings
        finding_json = json.dumps([{
            "severity": "medium",
            "title": "Suspicious outbound connection",
            "description": "curl connected to 93.184.216.34 (US, Example ISP)",
            "affected_entities": ["curl", "93.184.216.34"],
            "evidence_event_ids": [1, 2],
            "recommendation": "Investigate",
            "chain": [],
        }])
        second_response = _mock_choice(finding_json, finish_reason="stop")

        analyzer._client = MagicMock()
        analyzer._client.chat.completions.create.side_effect = [
            first_response,
            second_response,
        ]

        patcher = _patch_kuzu()
        try:
            with patch(
                "agent.analyzer.tools.ToolExecutor.execute",
                return_value='{"country": "US", "isp": "Example ISP"}',
            ):
                findings = analyzer.analyze_batch(events)
        finally:
            patcher.stop()

        assert len(findings) == 1
        assert findings[0].title == "Suspicious outbound connection"
        # Two LLM calls total
        assert analyzer._client.chat.completions.create.call_count == 2

    def test_max_iterations_forces_final(self):
        """When max iterations is exhausted, a forced final call is made."""
        self.settings.tool_use_max_iterations = 2
        analyzer = self._make_analyzer()
        events = _make_events()

        # Both iterations: LLM keeps requesting tools
        tool_call = _mock_tool_call("tc_1", "reverse_dns", {"ip": "93.184.216.34"})
        tool_response = _mock_choice(
            None, finish_reason="tool_calls", tool_calls=[tool_call]
        )

        # Forced final answer
        final_response = _mock_choice("[]", finish_reason="stop")

        analyzer._client = MagicMock()
        analyzer._client.chat.completions.create.side_effect = [
            tool_response,  # iter 1
            tool_response,  # iter 2
            final_response,  # forced final
        ]

        patcher = _patch_kuzu()
        try:
            with patch(
                "agent.analyzer.tools.ToolExecutor.execute",
                return_value='{"ip": "93.184.216.34", "hostname": "example.com"}',
            ):
                findings = analyzer.analyze_batch(events)
        finally:
            patcher.stop()

        assert findings == []
        # 2 iterations + 1 forced final = 3 calls
        assert analyzer._client.chat.completions.create.call_count == 3

    def test_tool_error_continues_loop(self):
        """Tool error returns JSON error, loop continues normally."""
        analyzer = self._make_analyzer()
        events = _make_events()

        # First: LLM calls a tool
        tool_call = _mock_tool_call("tc_1", "ip_geolocation", {"ip": "0.0.0.0"})
        first_response = _mock_choice(
            None, finish_reason="tool_calls", tool_calls=[tool_call]
        )

        # Second: LLM produces final answer
        second_response = _mock_choice("[]", finish_reason="stop")

        analyzer._client = MagicMock()
        analyzer._client.chat.completions.create.side_effect = [
            first_response,
            second_response,
        ]

        patcher = _patch_kuzu()
        try:
            with patch(
                "agent.analyzer.tools.ToolExecutor.execute",
                return_value='{"error": "connection refused"}',
            ):
                findings = analyzer.analyze_batch(events)
        finally:
            patcher.stop()

        assert findings == []
        assert analyzer._client.chat.completions.create.call_count == 2

    def test_tools_disabled_falls_back(self):
        """With tool_use_enabled=False, uses single-shot path."""
        self.settings.tool_use_enabled = False
        analyzer = self._make_analyzer()
        events = _make_events()

        assert analyzer._tools == []

        mock_response = _mock_choice("[]", finish_reason="stop")
        analyzer._client = MagicMock()
        analyzer._client.chat.completions.create.return_value = mock_response

        patcher = _patch_kuzu()
        try:
            findings = analyzer.analyze_batch(events)
        finally:
            patcher.stop()

        assert findings == []
        # Single call, no tools param
        call_kwargs = analyzer._client.chat.completions.create.call_args
        assert "tools" not in call_kwargs.kwargs
