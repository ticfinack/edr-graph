"""Tool schemas and executor for LLM tool-use investigation.

Provides OpenAI function-calling schemas and a :class:`ToolExecutor` that
dispatches calls to external APIs (Tier 1/2) and local data (Tier 3).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import socket
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
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

TIER4_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "file_info",
            "description": (
                "Get metadata about a file: size, permissions, owner, timestamps, "
                "and code signature (macOS). Does NOT read file contents. "
                "Use this to check suspicious files referenced in events."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": (
                "List directory contents sorted by modification time (newest first). "
                "Shows name, type, size, and modification time for each entry."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the directory.",
                    },
                    "max_entries": {
                        "type": "integer",
                        "description": "Maximum entries to return (default 50).",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "process_info",
            "description": (
                "Get detailed information about a running process by PID: "
                "name, exe path, command line, parent PID, user, network "
                "connections, open files, child processes, and memory usage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "The process ID to inspect.",
                    }
                },
                "required": ["pid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "netstat_query",
            "description": (
                "Query active network connections, optionally filtered by PID "
                "or port. Returns matching connections with PID, process name, "
                "local/remote addresses."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Filter by process ID (optional).",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Filter by local or remote port (optional).",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "file_hash",
            "description": (
                "Compute MD5, SHA1, and SHA256 hashes for a file. Use the SHA256 "
                "result with virustotal_lookup(indicator=sha256, indicator_type='files') "
                "to check file reputation. Files over 100 MB are rejected."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file.",
                    }
                },
                "required": ["path"],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Sensitive path denylist (Tier 4 safety)
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: set[str] = {
    "/etc/shadow",
    "/etc/master.passwd",
    "/private/etc/shadow",
    "/private/etc/master.passwd",
}

_SENSITIVE_PATTERNS: list[str] = [
    "/.ssh/id_",
    "/.gnupg/",
    "/Keychains/",
    ".keychain-db",
    "/.aws/credentials",
    "/.aws/config",
    "/.config/gcloud/",
    "/.azure/",
]


def _is_sensitive_path(path: str) -> bool:
    """Check if a path points to a sensitive location. Resolves symlinks first."""
    try:
        resolved = str(Path(path).resolve())
    except (OSError, ValueError):
        resolved = path

    if resolved in _SENSITIVE_PATHS:
        return True

    return any(pattern in resolved for pattern in _SENSITIVE_PATTERNS)


def get_active_tools(settings: Settings) -> list[dict[str, Any]]:
    """Return the list of tool schemas based on configured API keys."""
    tools: list[dict[str, Any]] = list(TIER1_TOOLS) + list(TIER3_TOOLS)

    if settings.abuseipdb_api_key:
        tools.append(TIER2_TOOLS[0])  # abuseipdb_check
    if settings.virustotal_api_key:
        tools.append(TIER2_TOOLS[1])  # virustotal_lookup

    if settings.investigation_tools_enabled:
        tools.extend(TIER4_TOOLS)

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
            result = json.dumps({"error": f"Unknown tool: {tool_name}"}) if handler is None else handler(**arguments)
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
        return json.dumps(
            {
                "ip": ip,
                "abuse_confidence_score": report.get("abuseConfidenceScore"),
                "total_reports": report.get("totalReports"),
                "usage_type": report.get("usageType"),
                "isp": report.get("isp"),
                "country_code": report.get("countryCode"),
                "is_tor": report.get("isTor"),
            }
        )

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
        return json.dumps(
            {
                "indicator": indicator,
                "type": indicator_type,
                "last_analysis_stats": attrs.get("last_analysis_stats"),
                "reputation": attrs.get("reputation"),
                "tags": attrs.get("tags", []),
            }
        )

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

    # -- Tier 4 handlers (local host inspection) ----------------------------

    def _handle_file_info(self, path: str) -> str:
        if _is_sensitive_path(path):
            return json.dumps({"error": "access denied: sensitive path"})

        try:
            resolved = Path(path).resolve()
            st = resolved.stat()
        except FileNotFoundError:
            return json.dumps({"error": f"file not found: {path}"})
        except PermissionError:
            return json.dumps({"error": f"permission denied: {path}"})
        except OSError as exc:
            return json.dumps({"error": str(exc)})

        from datetime import datetime as _dt

        result: dict[str, Any] = {
            "path": str(resolved),
            "size": st.st_size,
            "permissions": stat.filemode(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "modified": _dt.fromtimestamp(st.st_mtime).isoformat(),
            "created": _dt.fromtimestamp(st.st_ctime).isoformat(),
            "accessed": _dt.fromtimestamp(st.st_atime).isoformat(),
            "is_symlink": Path(path).is_symlink(),
        }

        # Owner name
        try:
            import pwd

            result["owner"] = pwd.getpwuid(st.st_uid).pw_name
        except (ImportError, KeyError):
            pass
        try:
            import grp

            result["group"] = grp.getgrgid(st.st_gid).gr_name
        except (ImportError, KeyError):
            pass

        # macOS code signature
        if os.uname().sysname == "Darwin" and resolved.is_file():
            try:
                proc = subprocess.run(
                    ["codesign", "-dvv", str(resolved)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = proc.stderr  # codesign outputs to stderr
                sig: dict[str, str] = {}
                for line in output.splitlines():
                    if "=" in line:
                        key, _, val = line.partition("=")
                        key = key.strip()
                        if key in ("Authority", "TeamIdentifier", "Identifier"):
                            sig[key.lower()] = val.strip()
                if sig:
                    result["code_signature"] = sig
                elif proc.returncode != 0:
                    result["code_signature"] = "unsigned"
            except Exception:
                pass

        return json.dumps(result)

    def _handle_list_directory(self, path: str, max_entries: int = 50) -> str:
        if _is_sensitive_path(path):
            return json.dumps({"error": "access denied: sensitive path"})

        try:
            dir_path = Path(path).resolve()
            if not dir_path.is_dir():
                return json.dumps({"error": f"not a directory: {path}"})
        except (OSError, ValueError) as exc:
            return json.dumps({"error": str(exc)})

        from datetime import datetime as _dt

        entries = []
        try:
            items = list(dir_path.iterdir())
        except PermissionError:
            return json.dumps({"error": f"permission denied: {path}"})

        # Sort by modification time descending
        def _mtime(p: Path) -> float:
            try:
                return p.stat().st_mtime
            except OSError:
                return 0.0

        items.sort(key=_mtime, reverse=True)

        for item in items[:max_entries]:
            try:
                item_stat = item.stat()
                entries.append(
                    {
                        "name": item.name,
                        "type": "dir" if item.is_dir() else "file",
                        "size": item_stat.st_size,
                        "modified": _dt.fromtimestamp(item_stat.st_mtime).isoformat(),
                    }
                )
            except OSError:
                entries.append({"name": item.name, "type": "unknown"})

        return json.dumps(
            {
                "path": str(dir_path),
                "entries": entries,
                "total": len(items),
                "showing": len(entries),
            }
        )

    def _handle_process_info(self, pid: int) -> str:
        try:
            import psutil
        except ImportError:
            return json.dumps({"error": "psutil not available"})

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return json.dumps({"error": f"no such process: PID {pid}"})
        except psutil.AccessDenied:
            return json.dumps({"error": f"access denied: PID {pid}"})

        result: dict[str, Any] = {
            "pid": pid,
            "name": proc.name(),
            "status": proc.status(),
        }

        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            result["exe"] = proc.exe()
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            result["cmdline"] = proc.cmdline()
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            result["ppid"] = proc.ppid()
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            result["username"] = proc.username()
        with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
            result["create_time"] = proc.create_time()

        # Network connections
        try:
            conns = proc.net_connections(kind="inet")
            result["connections"] = [
                {
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status,
                }
                for c in conns[:20]
            ]
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Open files
        try:
            files = proc.open_files()
            result["open_files"] = [f.path for f in files[:20]]
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Children
        try:
            children = proc.children()
            result["children"] = [{"pid": c.pid, "name": c.name()} for c in children[:10]]
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Memory
        try:
            mem = proc.memory_info()
            result["memory"] = {
                "rss": mem.rss,
                "vms": mem.vms,
            }
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return json.dumps(result)

    def _handle_netstat_query(self, pid: int | None = None, port: int | None = None) -> str:
        try:
            import psutil
        except ImportError:
            return json.dumps({"error": "psutil not available"})

        connections = []
        try:
            all_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return json.dumps({"error": "access denied querying connections"})

        for c in all_conns:
            # Filter by PID
            if pid is not None and c.pid != pid:
                continue

            # Filter by port
            if port is not None:
                local_match = c.laddr and c.laddr.port == port
                remote_match = c.raddr and c.raddr.port == port
                if not local_match and not remote_match:
                    continue

            # Get process name
            proc_name = ""
            if c.pid:
                with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = psutil.Process(c.pid).name()

            connections.append(
                {
                    "pid": c.pid,
                    "process": proc_name,
                    "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status,
                }
            )

            if len(connections) >= 50:
                break

        return json.dumps(
            {
                "connections": connections,
                "count": len(connections),
                "filters": {"pid": pid, "port": port},
            }
        )

    def _handle_file_hash(self, path: str) -> str:
        if _is_sensitive_path(path):
            return json.dumps({"error": "access denied: sensitive path"})

        try:
            resolved = Path(path).resolve()
            size = resolved.stat().st_size
        except FileNotFoundError:
            return json.dumps({"error": f"file not found: {path}"})
        except PermissionError:
            return json.dumps({"error": f"permission denied: {path}"})
        except OSError as exc:
            return json.dumps({"error": str(exc)})

        # 100 MB size cap
        if size > 100 * 1024 * 1024:
            return json.dumps({"error": f"file too large: {size} bytes (max 100 MB)"})

        if not resolved.is_file():
            return json.dumps({"error": f"not a regular file: {path}"})

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(resolved, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except PermissionError:
            return json.dumps({"error": f"permission denied: {path}"})

        return json.dumps(
            {
                "path": str(resolved),
                "size": size,
                "md5": md5.hexdigest(),
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
        )

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
