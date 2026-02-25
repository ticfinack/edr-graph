"""Read-only query interface for the forensic ledger.

Opens its own WAL connection for concurrent reads while the writer
thread holds the write connection.  All queries return ``LedgerRow``
namedtuples with both raw columns and deserialized OCSF/entities.
"""

from __future__ import annotations

import contextlib
import csv
import json
import logging
import os
import sqlite3
from collections import namedtuple
from datetime import datetime
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("agent.ledger.reader")

LedgerRow = namedtuple("LedgerRow", [
    "id", "ts", "event_type", "hostname", "pid", "parent_pid",
    "process_name", "username", "remote_ip", "remote_port",
    "ocsf_json", "entities_json", "ocsf", "entities",
])


class LedgerReader:
    """Read-only query interface to the forensic ledger SQLite database."""

    def __init__(self, data_dir: Path | str) -> None:
        self._db_path = Path(data_dir).resolve() / "forensic_ledger.db"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_ledger_row(self, row: sqlite3.Row, deserialize: bool = True) -> LedgerRow:
        ocsf = None
        entities = None
        if deserialize:
            try:
                from agent.ledger.serializer import deserialize_entities, deserialize_ocsf
                if row["ocsf_json"]:
                    ocsf = deserialize_ocsf(row["ocsf_json"])
                if row["entities_json"]:
                    entities = deserialize_entities(row["entities_json"])
            except Exception:
                logger.debug("Deserialization failed for row %d", row["id"], exc_info=True)

        return LedgerRow(
            id=row["id"],
            ts=row["ts"],
            event_type=row["event_type"],
            hostname=row["hostname"],
            pid=row["pid"],
            parent_pid=row["parent_pid"],
            process_name=row["process_name"],
            username=row["username"],
            remote_ip=row["remote_ip"],
            remote_port=row["remote_port"],
            ocsf_json=row["ocsf_json"],
            entities_json=row["entities_json"],
            ocsf=ocsf,
            entities=entities,
        )

    def query_time_range(
        self,
        start: float,
        end: float,
        event_types: list[str] | None = None,
        limit: int = 1000,
    ) -> list[LedgerRow]:
        """Query events within a time range, optionally filtered by event type."""
        conn = self._connect()
        try:
            if event_types:
                placeholders = ", ".join("?" for _ in event_types)
                sql = (
                    f"SELECT * FROM forensic_ledger "
                    f"WHERE ts >= ? AND ts <= ? AND event_type IN ({placeholders}) "
                    f"ORDER BY ts DESC LIMIT ?"
                )
                params = [start, end] + event_types + [limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE ts >= ? AND ts <= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [start, end, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def query_by_pid(self, pid: int, since: float | None = None, limit: int = 500) -> list[LedgerRow]:
        """Query events for a specific PID."""
        conn = self._connect()
        try:
            if since is not None:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE pid = ? AND ts >= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [pid, since, limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE pid = ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [pid, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def query_by_ip(self, ip: str, since: float | None = None, limit: int = 500) -> list[LedgerRow]:
        """Query events involving a specific remote IP."""
        conn = self._connect()
        try:
            if since is not None:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE remote_ip = ? AND ts >= ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [ip, since, limit]
            else:
                sql = (
                    "SELECT * FROM forensic_ledger "
                    "WHERE remote_ip = ? "
                    "ORDER BY ts DESC LIMIT ?"
                )
                params = [ip, limit]

            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_ledger_row(r) for r in rows]
        finally:
            conn.close()

    def get_stats(self) -> dict:
        """Return ledger statistics: row count, oldest/newest ts, DB size."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*), MIN(ts), MAX(ts) FROM forensic_ledger"
            ).fetchone()
            db_size = 0
            with contextlib.suppress(OSError):
                db_size = os.path.getsize(str(self._db_path))

            return {
                "row_count": row[0] or 0,
                "oldest_ts": row[1],
                "newest_ts": row[2],
                "db_size_bytes": db_size,
            }
        finally:
            conn.close()

    def iter_entities(self, start: float, end: float) -> Iterator:
        """Yield deserialized ExtractedEntities for a time range.

        Used by the slicer to bulk-read entities for graph rebuilding.
        Streams results to avoid loading all rows into memory at once.
        """
        from agent.ledger.serializer import deserialize_entities

        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        try:
            cursor = conn.execute(
                "SELECT entities_json FROM forensic_ledger "
                "WHERE ts >= ? AND ts <= ? AND entities_json IS NOT NULL "
                "ORDER BY ts ASC",
                (start, end),
            )
            while True:
                row = cursor.fetchone()
                if row is None:
                    break
                try:
                    yield deserialize_entities(row[0])
                except Exception:
                    logger.debug("Failed to deserialize entities row", exc_info=True)
        finally:
            conn.close()

    def export_entities_csv(self, start: float, end: float, output_dir: str) -> dict[str, str]:
        """Export deduplicated entities to CSV files for Kuzu COPY FROM.

        Streams entities_json from SQLite, deduplicates nodes by ID
        (keeping latest timestamps), and writes one CSV per node/edge table.

        Returns a dict mapping table name -> CSV file path (only for non-empty tables).
        """
        # Accumulators: nodes deduplicated by ID, edges collected in lists
        users: dict[str, dict] = {}
        processes: dict[str, dict] = {}
        ips: dict[str, dict] = {}
        domains: dict[str, dict] = {}
        files: dict[str, dict] = {}
        registry_keys: dict[str, dict] = {}
        # Edge lists keyed by rel table name
        edges: dict[str, list[list]] = {
            "SPAWNED": [],
            "CONNECTED_TO": [],
            "RESOLVED": [],
            "RESOLVES_TO": [],
            "CREATED_FILE": [],
            "MODIFIED_FILE": [],
            "READ_FILE": [],
            "DELETED_FILE": [],
            "CREATED_REG": [],
            "MODIFIED_REG": [],
            "DELETED_REG": [],
            "LISTENING_ON": [],
        }

        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        row_count = 0
        try:
            cursor = conn.execute(
                "SELECT entities_json FROM forensic_ledger "
                "WHERE ts >= ? AND ts <= ? AND entities_json IS NOT NULL "
                "ORDER BY ts ASC",
                (start, end),
            )
            while True:
                row = cursor.fetchone()
                if row is None:
                    break
                row_count += 1
                try:
                    data = json.loads(row[0])
                except Exception:
                    continue

                # Deduplicate nodes by ID (last write wins for processes,
                # latest last_seen wins for timestamped nodes)
                for u in data.get("users", []):
                    uid = u.get("id", "")
                    if uid and (uid not in users or _ts_newer(u, users[uid], "last_seen")):
                        users[uid] = u
                for p in data.get("processes", []):
                    pid = p.get("id", "")
                    if pid:
                        processes[pid] = p
                for ip in data.get("ips", []):
                    ipid = ip.get("id", "")
                    if ipid and (ipid not in ips or _ts_newer(ip, ips[ipid], "last_seen")):
                        ips[ipid] = ip
                for d in data.get("domains", []):
                    did = d.get("id", "")
                    if did and (did not in domains or _ts_newer(d, domains[did], "last_seen")):
                        domains[did] = d
                for f in data.get("files", []):
                    fid = f.get("id", "")
                    if fid and (fid not in files or _ts_newer(f, files[fid], "last_seen")):
                        files[fid] = f
                for r in data.get("registry_keys", []):
                    rid = r.get("id", "")
                    if rid and (rid not in registry_keys or _ts_newer(r, registry_keys[rid], "last_seen")):
                        registry_keys[rid] = r

                # Collect edges
                for e in data.get("spawned_edges", []):
                    edges["SPAWNED"].append(e)
                for e in data.get("connected_edges", []):
                    edges["CONNECTED_TO"].append(e)
                for e in data.get("resolved_edges", []):
                    edges["RESOLVED"].append(e)
                for e in data.get("resolves_to_edges", []):
                    edges["RESOLVES_TO"].append(e)
                for e in data.get("file_edges", []):
                    op = e.get("operation", "MODIFIED")
                    tbl = {"CREATED": "CREATED_FILE", "MODIFIED": "MODIFIED_FILE",
                           "READ": "READ_FILE", "DELETED": "DELETED_FILE"}.get(op, "MODIFIED_FILE")
                    edges[tbl].append(e)
                for e in data.get("registry_edges", []):
                    op = e.get("operation", "MODIFIED")
                    tbl = {"CREATED": "CREATED_REG", "MODIFIED": "MODIFIED_REG",
                           "DELETED": "DELETED_REG"}.get(op, "MODIFIED_REG")
                    edges[tbl].append(e)
        finally:
            conn.close()

        logger.info(
            "Ledger export: %d rows → %d procs, %d users, %d IPs, %d domains, %d files",
            row_count, len(processes), len(users), len(ips), len(domains), len(files),
        )

        # Build sets of valid node IDs for edge validation
        valid_users = set(users.keys())
        valid_procs = set(processes.keys())
        valid_ips = set(ips.keys())
        valid_domains = set(domains.keys())
        valid_files = set(files.keys())
        valid_regs = set(registry_keys.keys())

        result: dict[str, str] = {}

        # ── Write node CSVs ──
        if users:
            path = os.path.join(output_dir, "users.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "name", "uid", "first_seen", "last_seen"])
                for u in users.values():
                    w.writerow([
                        u["id"], u.get("name", ""), u.get("uid", ""),
                        _fmt_ts(u.get("first_seen")), _fmt_ts(u.get("last_seen")),
                    ])
            result["User"] = path

        if processes:
            path = os.path.join(output_dir, "processes.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "name", "pid", "cmd_line", "exe_path", "hostname",
                            "start_time", "parent_pid", "bundle_id", "code_signed",
                            "signing_authority"])
                for p in processes.values():
                    w.writerow([
                        p["id"], p.get("name", ""), p.get("pid", 0),
                        p.get("cmd_line", ""), p.get("exe_path", ""),
                        p.get("hostname", ""), _fmt_ts(p.get("start_time")),
                        p.get("parent_pid", 0) or 0,
                        p.get("bundle_id", ""),
                        str(p.get("code_signed", False)).lower() if p.get("code_signed") is not None else "false",
                        p.get("signing_authority", ""),
                    ])
            result["Process"] = path

        if ips:
            path = os.path.join(output_dir, "ips.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "address", "is_private", "first_seen", "last_seen",
                            "country", "city", "isp", "org", "asn",
                            "is_hosting", "is_proxy", "classification",
                            "provider_name", "reverse_dns"])
                for ip in ips.values():
                    w.writerow([
                        ip["id"], ip.get("address", ""),
                        str(ip.get("is_private", False)).lower(),
                        _fmt_ts(ip.get("first_seen")), _fmt_ts(ip.get("last_seen")),
                        ip.get("country", ""), ip.get("city", ""),
                        ip.get("isp", ""), ip.get("org", ""), ip.get("asn", ""),
                        str(ip.get("is_hosting", False)).lower(),
                        str(ip.get("is_proxy", False)).lower(),
                        ip.get("classification", "unclassified"),
                        ip.get("provider_name", ""), ip.get("reverse_dns", ""),
                    ])
            result["IP"] = path

        if domains:
            path = os.path.join(output_dir, "domains.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "name", "first_seen", "last_seen",
                            "is_dga_candidate", "tld"])
                for d in domains.values():
                    w.writerow([
                        d["id"], d.get("name", ""),
                        _fmt_ts(d.get("first_seen")), _fmt_ts(d.get("last_seen")),
                        str(d.get("is_dga_candidate", False)).lower(),
                        d.get("tld", ""),
                    ])
            result["Domain"] = path

        if files:
            path = os.path.join(output_dir, "files.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "path", "hash_sha256", "size", "first_seen", "last_seen"])
                for fi in files.values():
                    w.writerow([
                        fi["id"], fi.get("path", ""),
                        fi.get("hash_sha256", "") or "",
                        fi.get("size", 0) or 0,
                        _fmt_ts(fi.get("first_seen")), _fmt_ts(fi.get("last_seen")),
                    ])
            result["File"] = path

        if registry_keys:
            path = os.path.join(output_dir, "registry_keys.csv")
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "path", "value_name", "value_data",
                            "previous_data", "first_seen", "last_seen"])
                for r in registry_keys.values():
                    w.writerow([
                        r["id"], r.get("path", ""),
                        r.get("value_name", "") or "",
                        r.get("value_data", "") or "",
                        r.get("previous_data", "") or "",
                        _fmt_ts(r.get("first_seen")), _fmt_ts(r.get("last_seen")),
                    ])
            result["RegistryKey"] = path

        # ── Write edge CSVs (with dangling-reference filtering) ──
        _write_edge_csv(edges, "SPAWNED", output_dir, result,
                        ["user_id", "process_id", "timestamp", "activity_id", "event_id"],
                        valid_users, valid_procs, "user_id", "process_id")
        _write_edge_csv(edges, "CONNECTED_TO", output_dir, result,
                        ["process_id", "ip_id", "timestamp", "dst_port", "protocol", "direction", "event_id"],
                        valid_procs, valid_ips, "process_id", "ip_id")
        _write_edge_csv(edges, "RESOLVED", output_dir, result,
                        ["process_id", "domain_id", "timestamp", "event_id"],
                        valid_procs, valid_domains, "process_id", "domain_id")
        _write_edge_csv(edges, "RESOLVES_TO", output_dir, result,
                        ["domain_id", "ip_id", "timestamp", "event_id"],
                        valid_domains, valid_ips, "domain_id", "ip_id")
        for tbl in ("CREATED_FILE", "MODIFIED_FILE", "READ_FILE", "DELETED_FILE"):
            _write_edge_csv(edges, tbl, output_dir, result,
                            ["process_id", "file_id", "timestamp", "event_id"],
                            valid_procs, valid_files, "process_id", "file_id")
        for tbl in ("CREATED_REG", "MODIFIED_REG", "DELETED_REG"):
            _write_edge_csv(edges, tbl, output_dir, result,
                            ["process_id", "registry_id", "timestamp", "event_id"],
                            valid_procs, valid_regs, "process_id", "registry_id")

        return result


def _fmt_ts(val) -> str:
    """Format a datetime value (string or datetime) to Kuzu timestamp format."""
    if val is None:
        return "2000-01-01 00:00:00"
    if isinstance(val, str):
        # ISO format → Kuzu format
        with contextlib.suppress(ValueError):
            dt = datetime.fromisoformat(val)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return val[:19].replace("T", " ") if len(val) >= 19 else "2000-01-01 00:00:00"
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    return "2000-01-01 00:00:00"


def _ts_newer(a: dict, b: dict, field: str) -> bool:
    """Return True if a[field] is newer than b[field]."""
    va, vb = a.get(field, ""), b.get(field, "")
    if not va:
        return False
    if not vb:
        return True
    return str(va) > str(vb)


def _write_edge_csv(
    edges: dict[str, list],
    table_name: str,
    output_dir: str,
    result: dict[str, str],
    field_keys: list[str],
    valid_from: set[str],
    valid_to: set[str],
    from_key: str,
    to_key: str,
) -> None:
    """Write a CSV file for an edge table, filtering out dangling references."""
    edge_list = edges.get(table_name, [])
    if not edge_list:
        return

    # Filter edges to only those referencing valid nodes
    valid_edges = [
        e for e in edge_list
        if e.get(from_key) in valid_from and e.get(to_key) in valid_to
    ]
    if not valid_edges:
        return

    path = os.path.join(output_dir, f"{table_name.lower()}.csv")
    # CSV header: from_id, to_id, then remaining properties
    header = ["from", "to"] + [k for k in field_keys if k != from_key and k != to_key]

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for e in valid_edges:
            row = [e.get(from_key, ""), e.get(to_key, "")]
            for k in field_keys:
                if k in (from_key, to_key):
                    continue
                val = e.get(k, "")
                if k == "timestamp":
                    val = _fmt_ts(val)
                row.append(val if val is not None else "")
            w.writerow(row)

    result[table_name] = path
