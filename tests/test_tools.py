"""Tests for tool schemas, cache, and executor."""

import json
import time
from unittest.mock import MagicMock, patch

from agent.analyzer.tool_cache import ToolCache
from agent.analyzer.tools import (
    ToolExecutor,
    get_active_tools,
)
from agent.config import Settings
from agent.intel.mitre_attack import lookup


class TestGetActiveTools:
    def test_tier1_only(self):
        """No Tier 2 keys configured → only Tier 1 + Tier 3 tools."""
        settings = Settings(
            deepinfra_api_key="test",
            abuseipdb_api_key="",
            virustotal_api_key="",
        )
        tools = get_active_tools(settings)
        names = {t["function"]["name"] for t in tools}
        # Tier 1
        assert "ip_geolocation" in names
        assert "reverse_dns" in names
        assert "whois_lookup" in names
        # Tier 3
        assert "mitre_attack_lookup" in names
        assert "graph_context_query" in names
        # Tier 2 absent
        assert "abuseipdb_check" not in names
        assert "virustotal_lookup" not in names

    def test_with_keys(self):
        """With API keys → all tiers present."""
        settings = Settings(
            deepinfra_api_key="test",
            abuseipdb_api_key="abuse-key",
            virustotal_api_key="vt-key",
        )
        tools = get_active_tools(settings)
        names = {t["function"]["name"] for t in tools}
        assert "abuseipdb_check" in names
        assert "virustotal_lookup" in names
        # Tier 1 + 3 still there
        assert "ip_geolocation" in names
        assert "mitre_attack_lookup" in names


class TestToolCache:
    def test_hit_miss(self):
        cache = ToolCache()
        cache.put("ip_geolocation", {"ip": "8.8.8.8"}, '{"country": "US"}')

        # Hit
        result = cache.get("ip_geolocation", {"ip": "8.8.8.8"})
        assert result == '{"country": "US"}'

        # Miss — different args
        result = cache.get("ip_geolocation", {"ip": "1.1.1.1"})
        assert result is None

        # Miss — different tool
        result = cache.get("reverse_dns", {"ip": "8.8.8.8"})
        assert result is None

    def test_ttl_expiry(self):
        cache = ToolCache(ttl=0.05)
        cache.put("test", {"k": "v"}, "result")
        assert cache.get("test", {"k": "v"}) == "result"
        time.sleep(0.06)
        assert cache.get("test", {"k": "v"}) is None

    def test_size(self):
        cache = ToolCache()
        assert cache.size == 0
        cache.put("a", {}, "1")
        cache.put("b", {}, "2")
        assert cache.size == 2


class TestToolExecutor:
    def setup_method(self):
        self.settings = Settings(deepinfra_api_key="test")
        self.mock_db = MagicMock()
        self.cache = ToolCache()
        self.executor = ToolExecutor(self.settings, self.mock_db, self.cache)

    def test_reverse_dns_localhost(self):
        result = json.loads(self.executor.execute("reverse_dns", {"ip": "127.0.0.1"}))
        assert result["ip"] == "127.0.0.1"
        assert result["hostname"] is not None  # Should resolve to localhost

    def test_tool_error_returns_json(self):
        """Network errors return error JSON, never raise."""
        with patch.object(ToolExecutor, "_http_get_json", side_effect=RuntimeError("connection refused")):
            result = json.loads(self.executor.execute("ip_geolocation", {"ip": "0.0.0.0"}))
        assert "error" in result

    def test_unknown_tool(self):
        result = json.loads(self.executor.execute("nonexistent_tool", {}))
        assert "error" in result
        assert "Unknown tool" in result["error"]

    def test_cache_prevents_duplicate_calls(self):
        """Second call with same args should hit cache, not execute again."""
        with patch.object(ToolExecutor, "_http_get_json", return_value={"country": "US"}) as mock_http:
            self.executor.execute("ip_geolocation", {"ip": "8.8.8.8"})
            self.executor.execute("ip_geolocation", {"ip": "8.8.8.8"})
        mock_http.assert_called_once()


class TestMitreLookup:
    def test_lookup_by_id(self):
        results = lookup("T1059.004")
        assert len(results) == 1
        assert results[0]["name"] == "Unix Shell"
        assert results[0]["id"] == "T1059.004"

    def test_lookup_by_keyword(self):
        results = lookup("powershell")
        assert len(results) >= 1
        names = [r["name"] for r in results]
        assert "PowerShell" in names

    def test_lookup_no_match(self):
        results = lookup("zzz_nonexistent_technique_zzz")
        assert results == []

    def test_lookup_max_5(self):
        """Keyword search should return at most 5 results."""
        results = lookup("adversaries")  # very common word
        assert len(results) <= 5
