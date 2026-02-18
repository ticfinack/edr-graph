"""Tool schemas and executor for LLM tool-use investigation.

Provides OpenAI function-calling schemas and a :class:`ToolExecutor` that
dispatches calls to external APIs (Tier 1/2) and local data (Tier 3).
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any

import kuzu

from agent.config import Settings
from agent.intel import mitre_attack

from .tool_cache import ToolCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OpenAI function-calling schemas
# ---------------------------------------------------------------------------

TIER1_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ip_geolocation",
            "description": (
                "Get geolocation, ISP, organisation, AS number, and proxy/hosting "
                "flags for a public IP address. Do NOT use for RFC1918 private IPs "
                "(10.x, 172.16-31.x, 192.168.x)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The public IPv4 or IPv6 address to look up.",
                    }
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reverse_dns",
            "description": "Resolve an IP address to its reverse DNS hostname.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP address to resolve.",
                    }
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "whois_lookup",
            "description": (
                "Look up WHOIS registration data for a domain name — registrar, "
                "creation date, expiry, and registrant organization."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The domain name to query (e.g. 'example.com').",
                    }
                },
                "required": ["domain"],
            },
        },
    },
]

TIER2_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "abuseipdb_check",
            "description": (
                "Check an IP address against AbuseIPDB for abuse confidence score, "
                "total reports, usage type, ISP, and country."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP address to check.",
                    }
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "virustotal_lookup",
            "description": (
                "Look up an indicator (IP, domain, URL, or file hash) on VirusTotal. "
                "Returns detection ratio, reputation score, and tags."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The indicator value (IP, domain, URL, or hash).",
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip-addresses", "domains", "urls", "files"],
                        "description": "Type of indicator.",
                    },
                },
                "required": ["indicator", "indicator_type"],
            },
        },
    },
]

TIER3_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "mitre_attack_lookup",
            "description": (
                "Look up MITRE ATT&CK techniques by ID (e.g. 'T1059.004') or "
                "keyword (e.g. 'powershell'). Returns technique name, tactic, "
                "description, and mitigations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Technique ID or search keyword.",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "graph_context_query",
            "description": (
                "Deep-dive on any entity in the local graph database. Query recent "
                "activity for a user, process, or IP address."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "enum": ["user", "process", "ip"],
                        "description": "Type of entity to query.",
                    },
                    "entity_id": {
                        "type": "string",
                        "description": "Entity identifier (username, process name, or IP address).",
                    },
                },
                "required": ["entity_type", "entity_id"],
            },
        },
    },
]


def get_active_tools(settings: Settings) -> list[dict[str, Any]]:
    """Return the list of tool schemas based on configured API keys."""
    tools: list[dict[str, Any]] = list(TIER1_TOOLS) + list(TIER3_TOOLS)

    if settings.abuseipdb_api_key:
        tools.append(TIER2_TOOLS[0])  # abuseipdb_check
    if settings.virustotal_api_key:
        tools.append(TIER2_TOOLS[1])  # virustotal_lookup

    return tools


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT = 5  # seconds


class ToolExecutor:
    """Executes tool calls, caching results per-batch.

    All handler methods return a JSON string.  Errors are caught and returned
    as ``{"error": "..."}`` so the LLM can incorporate the failure gracefully.
    """

    def __init__(
        self,
        settings: Settings,
        kuzu_db: kuzu.Database,
        cache: ToolCache,
    ) -> None:
        self._settings = settings
        self._kuzu_db = kuzu_db
        self._cache = cache

    def execute(self, tool_name: str, arguments: dict) -> str:
        """Dispatch a tool call, checking cache first."""
        cached = self._cache.get(tool_name, arguments)
        if cached is not None:
            logger.debug("Tool cache hit: %s", tool_name)
            return cached

        try:
            handler = getattr(self, f"_handle_{tool_name}", None)
            if handler is None:
                result = json.dumps({"error": f"Unknown tool: {tool_name}"})
            else:
                result = handler(**arguments)
        except Exception as exc:
            logger.warning("Tool %s failed: %s", tool_name, exc)
            result = json.dumps({"error": str(exc)})

        self._cache.put(tool_name, arguments, result)
        return result

    # -- Tier 1 handlers ---------------------------------------------------

    def _handle_ip_geolocation(self, ip: str) -> str:
        fields = "status,message,country,regionName,city,isp,org,as,proxy,hosting,query"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        data = self._http_get_json(url)
        if data.get("status") == "fail":
            return json.dumps({"error": data.get("message", "lookup failed"), "query": ip})
        return json.dumps(data)

    def _handle_reverse_dns(self, ip: str) -> str:
        try:
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
            return json.dumps({"ip": ip, "hostname": hostname})
        except socket.herror:
            return json.dumps({"ip": ip, "hostname": None, "error": "no PTR record"})

    def _handle_whois_lookup(self, domain: str) -> str:
        url = f"https://who-dat.as93.net/{domain}"
        data = self._http_get_json(url)
        # Extract the most useful fields to keep token count low
        result: dict[str, Any] = {"domain": domain}
        if isinstance(data, dict):
            reg = data.get("registrar", {})
            if isinstance(reg, dict):
                result["registrar"] = reg.get("name")
            dates = data.get("dates", {})
            if isinstance(dates, dict):
                result["created"] = dates.get("created")
                result["expires"] = dates.get("expires")
                result["updated"] = dates.get("updated")
            registrant = data.get("registrant", {})
            if isinstance(registrant, dict):
                result["registrant_org"] = registrant.get("organization")
                result["registrant_country"] = registrant.get("country")
        return json.dumps(result)

    # -- Tier 2 handlers ---------------------------------------------------

    def _handle_abuseipdb_check(self, ip: str) -> str:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(
            url,
            headers={
                "Key": self._settings.abuseipdb_api_key,
                "Accept": "application/json",
            },
        )
        data = self._http_request_json(req)
        # Extract just the useful bits
        report = data.get("data", {})
        return json.dumps({
            "ip": ip,
            "abuse_confidence_score": report.get("abuseConfidenceScore"),
            "total_reports": report.get("totalReports"),
            "usage_type": report.get("usageType"),
            "isp": report.get("isp"),
            "country_code": report.get("countryCode"),
            "is_tor": report.get("isTor"),
        })

    def _handle_virustotal_lookup(self, indicator: str, indicator_type: str) -> str:
        url = f"https://www.virustotal.com/api/v3/{indicator_type}/{indicator}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self._settings.virustotal_api_key,
                "Accept": "application/json",
            },
        )
        data = self._http_request_json(req)
        attrs = data.get("data", {}).get("attributes", {})
        return json.dumps({
            "indicator": indicator,
            "type": indicator_type,
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
        })

    # -- Tier 3 handlers ---------------------------------------------------

    def _handle_mitre_attack_lookup(self, query: str) -> str:
        results = mitre_attack.lookup(query)
        if not results:
            return json.dumps({"query": query, "matches": [], "error": "no matches found"})
        return json.dumps({"query": query, "matches": results})

    def _handle_graph_context_query(self, entity_type: str, entity_id: str) -> str:
        conn = kuzu.Connection(self._kuzu_db)
        limit = self._settings.graph_context_limit
        rows: list[dict[str, Any]] = []

        try:
            if entity_type == "user":
                result = conn.execute(
                    "MATCH (u:User {id: $uid})-[r:SPAWNED]->(p:Process) "
                    "RETURN p.name AS process, p.cmd_line AS cmd, r.timestamp AS ts "
                    "ORDER BY r.timestamp DESC LIMIT $limit",
                    {"uid": entity_id, "limit": limit},
                )
                while result.has_next():
                    row = result.get_next()
                    rows.append({"process": row[0], "cmd_line": row[1], "timestamp": str(row[2])})

            elif entity_type == "process":
                result = conn.execute(
                    "MATCH (p:Process {name: $pname})-[c:CONNECTED_TO]->(ip:IP) "
                    "RETURN ip.address AS ip, c.dst_port AS port, c.timestamp AS ts "
                    "ORDER BY c.timestamp DESC LIMIT $limit",
                    {"pname": entity_id, "limit": limit},
                )
                while result.has_next():
                    row = result.get_next()
                    rows.append({"ip": row[0], "port": row[1], "timestamp": str(row[2])})

            elif entity_type == "ip":
                result = conn.execute(
                    "MATCH (p:Process)-[c:CONNECTED_TO]->(ip:IP {address: $addr}) "
                    "RETURN p.name AS process, c.dst_port AS port, c.timestamp AS ts "
                    "ORDER BY c.timestamp DESC LIMIT $limit",
                    {"addr": entity_id, "limit": limit},
                )
                while result.has_next():
                    row = result.get_next()
                    rows.append({"process": row[0], "port": row[1], "timestamp": str(row[2])})
            else:
                return json.dumps({"error": f"Unknown entity_type: {entity_type}"})
        except Exception as exc:
            return json.dumps({"error": f"Graph query failed: {exc}"})

        return json.dumps({"entity_type": entity_type, "entity_id": entity_id, "results": rows})

    # -- HTTP helpers -------------------------------------------------------

    @staticmethod
    def _http_get_json(url: str) -> dict:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        return ToolExecutor._http_request_json(req)

    @staticmethod
    def _http_request_json(req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            raise RuntimeError(str(exc)) from exc
