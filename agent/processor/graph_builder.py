"""Upsert nodes and create edges in Kuzu graph database."""

from __future__ import annotations

import logging
from datetime import datetime

import kuzu

from agent.graph.connection import get_connection
from agent.processor.entity_extractor import ExtractedEntities
from agent.schema.graph_types import (
    DomainNode,
    FileNode,
    IpNode,
    ProcessNode,
    RegistryKeyNode,
    UserNode,
)

logger = logging.getLogger(__name__)


def _naive(dt: datetime) -> datetime:
    """Strip timezone info so naive/aware datetimes can be compared."""
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


class GraphBuilder:
    """Writes extracted entities into the Kuzu graph.

    Uses a thread-local connection from agent.graph.connection.
    """

    def __init__(self, db: kuzu.Database, conn: kuzu.Connection | None = None) -> None:
        self._db = db
        if conn is not None:
            self._conn = conn
        else:
            try:
                self._conn = get_connection()
            except RuntimeError:
                # Test environment — shared connection not initialized
                self._conn = kuzu.Connection(db)

    def write_entities(self, entities: ExtractedEntities) -> None:
        """Upsert all nodes and create all edges from extracted entities."""
        self._write_entities_unlocked(entities)

    def _write_entities_unlocked(self, entities: ExtractedEntities) -> None:
        for user in entities.users:
            self._upsert_user(user)
        for proc in entities.processes:
            self._upsert_process(proc)
        for ip_node in entities.ips:
            self._upsert_ip(ip_node)
        for domain in entities.domains:
            self._upsert_domain(domain)
        for file_node in entities.files:
            self._upsert_file(file_node)
        for reg in entities.registry_keys:
            self._upsert_registry_key(reg)

        for edge in entities.spawned_edges:
            self._create_spawned_edge(edge)
        for edge in entities.connected_edges:
            self._create_connected_edge(edge)
        for edge in entities.resolved_edges:
            self._create_resolved_edge(edge)
        for edge in entities.resolves_to_edges:
            self._create_resolves_to_edge(edge)
        for edge in entities.file_edges:
            self._create_file_edge(edge)
        for edge in entities.registry_edges:
            self._create_registry_edge(edge)

    def write_batch(self, batch: list[ExtractedEntities]) -> None:
        """Deduplicate and write entities from an entire batch at once.

        Nodes are deduplicated by ID (keeping the latest timestamps).
        Edges are written as-is since each represents a distinct event.
        """
        self._write_batch_unlocked(batch)

    def _write_batch_unlocked(self, batch: list[ExtractedEntities]) -> None:
        users: dict[str, UserNode] = {}
        processes: dict[str, ProcessNode] = {}
        ips: dict[str, IpNode] = {}
        domains: dict[str, DomainNode] = {}
        files: dict[str, FileNode] = {}
        registry_keys: dict[str, RegistryKeyNode] = {}
        spawned: list[dict] = []
        connected: list[dict] = []
        resolved: list[dict] = []
        resolves_to: list[dict] = []
        file_edges: list[dict] = []
        registry_edges: list[dict] = []

        for entities in batch:
            for u in entities.users:
                existing = users.get(u.id)
                if existing is None or _naive(u.last_seen) > _naive(existing.last_seen):
                    users[u.id] = u
            for p in entities.processes:
                processes[p.id] = p  # last write wins (same data)
            for ip in entities.ips:
                existing = ips.get(ip.id)
                if existing is None or _naive(ip.last_seen) > _naive(existing.last_seen):
                    ips[ip.id] = ip
            for d in entities.domains:
                existing = domains.get(d.id)
                if existing is None or _naive(d.last_seen) > _naive(existing.last_seen):
                    domains[d.id] = d
            for f in entities.files:
                existing = files.get(f.id)
                if existing is None or _naive(f.last_seen) > _naive(existing.last_seen):
                    files[f.id] = f
            for r in entities.registry_keys:
                existing = registry_keys.get(r.id)
                if existing is None or _naive(r.last_seen) > _naive(existing.last_seen):
                    registry_keys[r.id] = r
            spawned.extend(entities.spawned_edges)
            connected.extend(entities.connected_edges)
            resolved.extend(entities.resolved_edges)
            resolves_to.extend(entities.resolves_to_edges)
            file_edges.extend(entities.file_edges)
            registry_edges.extend(entities.registry_edges)

        for user in users.values():
            self._upsert_user(user)
        for proc in processes.values():
            self._upsert_process(proc)
        for ip_node in ips.values():
            self._upsert_ip(ip_node)
        for domain in domains.values():
            self._upsert_domain(domain)
        for file_node in files.values():
            self._upsert_file(file_node)
        for reg in registry_keys.values():
            self._upsert_registry_key(reg)
        for edge in spawned:
            self._create_spawned_edge(edge)
        for edge in connected:
            self._create_connected_edge(edge)
        for edge in resolved:
            self._create_resolved_edge(edge)
        for edge in resolves_to:
            self._create_resolves_to_edge(edge)
        for edge in file_edges:
            self._create_file_edge(edge)
        for edge in registry_edges:
            self._create_registry_edge(edge)

    def _upsert_user(self, user: UserNode) -> None:
        try:
            ts_first = _ts_lit(user.first_seen)
            ts_last = _ts_lit(user.last_seen)
            self._conn.execute(
                f"MERGE (u:User {{id: $id}}) "
                f"ON CREATE SET u.name = $name, u.uid = $uid, "
                f"u.first_seen = timestamp('{ts_first}'), "
                f"u.last_seen = timestamp('{ts_last}') "
                f"ON MATCH SET u.last_seen = timestamp('{ts_last}')",
                {"id": user.id, "name": user.name or "", "uid": user.uid or ""},
            )
        except Exception:
            logger.debug("Failed to upsert user %s", user.id, exc_info=True)

    def _upsert_process(self, proc: ProcessNode) -> None:
        try:
            ts = _ts_lit(proc.start_time)
            self._conn.execute(
                f"MERGE (p:Process {{id: $id}}) "
                f"ON CREATE SET p.name = $name, p.pid = $pid, "
                f"p.cmd_line = $cmd_line, p.exe_path = $exe_path, "
                f"p.hostname = $hostname, p.start_time = timestamp('{ts}'), "
                f"p.parent_pid = $parent_pid, "
                f"p.bundle_id = $bundle_id, p.code_signed = $code_signed, "
                f"p.signing_authority = $signing_authority, "
                f"p.container_id = $container_id "
                f"ON MATCH SET p.bundle_id = CASE WHEN $bundle_id <> '' THEN $bundle_id ELSE p.bundle_id END, "
                f"p.code_signed = CASE WHEN $code_signed IS NOT NULL THEN $code_signed ELSE p.code_signed END, "
                f"p.signing_authority = CASE WHEN $signing_authority <> '' THEN $signing_authority ELSE p.signing_authority END, "
                f"p.parent_pid = CASE WHEN $parent_pid <> 0 THEN $parent_pid ELSE p.parent_pid END, "
                f"p.container_id = CASE WHEN $container_id <> '' THEN $container_id ELSE p.container_id END",
                {
                    "id": proc.id,
                    "name": proc.name,
                    "pid": proc.pid,
                    "cmd_line": proc.cmd_line or "",
                    "exe_path": proc.exe_path or "",
                    "hostname": proc.hostname,
                    "parent_pid": proc.parent_pid or 0,
                    "bundle_id": proc.bundle_id or "",
                    "code_signed": proc.code_signed,
                    "signing_authority": proc.signing_authority or "",
                    "container_id": proc.container_id or "",
                },
            )
            # Update in-memory PID index for fast dashboard queries
            from agent.graph.pid_index import get_pid_index

            get_pid_index().on_upsert(proc.id, proc.pid, proc.parent_pid or 0, proc.name)
        except Exception:
            logger.debug("Failed to upsert process %s", proc.id, exc_info=True)

    def _upsert_ip(self, ip_node: IpNode) -> None:
        try:
            ts_first = _ts_lit(ip_node.first_seen)
            ts_last = _ts_lit(ip_node.last_seen)
            self._conn.execute(
                f"MERGE (ip:IP {{id: $id}}) "
                f"ON CREATE SET ip.address = $address, ip.is_private = $is_private, "
                f"ip.first_seen = timestamp('{ts_first}'), "
                f"ip.last_seen = timestamp('{ts_last}'), "
                f"ip.country = $country, ip.city = $city, ip.isp = $isp, "
                f"ip.org = $org, ip.asn = $asn, ip.is_hosting = $is_hosting, "
                f"ip.is_proxy = $is_proxy, ip.classification = $classification, "
                f"ip.provider_name = $provider_name, ip.reverse_dns = $reverse_dns "
                f"ON MATCH SET ip.last_seen = timestamp('{ts_last}'), "
                f"ip.country = CASE WHEN $country <> '' THEN $country ELSE ip.country END, "
                f"ip.city = CASE WHEN $city <> '' THEN $city ELSE ip.city END, "
                f"ip.isp = CASE WHEN $isp <> '' THEN $isp ELSE ip.isp END, "
                f"ip.org = CASE WHEN $org <> '' THEN $org ELSE ip.org END, "
                f"ip.asn = CASE WHEN $asn <> '' THEN $asn ELSE ip.asn END, "
                f"ip.classification = CASE WHEN $classification <> 'unclassified' THEN $classification ELSE ip.classification END, "
                f"ip.provider_name = CASE WHEN $provider_name <> '' THEN $provider_name ELSE ip.provider_name END, "
                f"ip.reverse_dns = CASE WHEN $reverse_dns <> '' THEN $reverse_dns ELSE ip.reverse_dns END",
                {
                    "id": ip_node.id,
                    "address": ip_node.address,
                    "is_private": ip_node.is_private,
                    "country": ip_node.country,
                    "city": ip_node.city,
                    "isp": ip_node.isp,
                    "org": ip_node.org,
                    "asn": ip_node.asn,
                    "is_hosting": ip_node.is_hosting,
                    "is_proxy": ip_node.is_proxy,
                    "classification": ip_node.classification,
                    "provider_name": ip_node.provider_name,
                    "reverse_dns": ip_node.reverse_dns,
                },
            )
        except Exception:
            logger.debug("Failed to upsert IP %s", ip_node.id, exc_info=True)

    def upsert_ip_enrichment(self, ip_node: IpNode) -> None:
        """Public method to persist IP enrichment data from pre-enrichment.

        Only updates enrichment fields (country, city, isp, etc.), never
        overwrites good data with blanks.
        """
        try:
            self._conn.execute(
                "MERGE (ip:IP {id: $id}) "
                "ON CREATE SET ip.address = $address, ip.is_private = $is_private, "
                "ip.first_seen = timestamp($ts), ip.last_seen = timestamp($ts), "
                "ip.country = $country, ip.city = $city, ip.isp = $isp, "
                "ip.org = $org, ip.asn = $asn, ip.is_hosting = $is_hosting, "
                "ip.is_proxy = $is_proxy, ip.classification = $classification, "
                "ip.provider_name = $provider_name, ip.reverse_dns = $reverse_dns "
                "ON MATCH SET "
                "ip.country = CASE WHEN $country <> '' THEN $country ELSE ip.country END, "
                "ip.city = CASE WHEN $city <> '' THEN $city ELSE ip.city END, "
                "ip.isp = CASE WHEN $isp <> '' THEN $isp ELSE ip.isp END, "
                "ip.org = CASE WHEN $org <> '' THEN $org ELSE ip.org END, "
                "ip.asn = CASE WHEN $asn <> '' THEN $asn ELSE ip.asn END, "
                "ip.classification = CASE WHEN $classification <> 'unclassified' THEN $classification ELSE ip.classification END, "
                "ip.provider_name = CASE WHEN $provider_name <> '' THEN $provider_name ELSE ip.provider_name END, "
                "ip.reverse_dns = CASE WHEN $reverse_dns <> '' THEN $reverse_dns ELSE ip.reverse_dns END",
                {
                    "id": ip_node.id,
                    "address": ip_node.address,
                    "is_private": ip_node.is_private,
                    "ts": _ts_lit(ip_node.first_seen),
                    "country": ip_node.country,
                    "city": ip_node.city,
                    "isp": ip_node.isp,
                    "org": ip_node.org,
                    "asn": ip_node.asn,
                    "is_hosting": ip_node.is_hosting,
                    "is_proxy": ip_node.is_proxy,
                    "classification": ip_node.classification,
                    "provider_name": ip_node.provider_name,
                    "reverse_dns": ip_node.reverse_dns,
                },
            )
        except Exception:
            logger.debug("Failed to upsert IP enrichment for %s", ip_node.id, exc_info=True)

    def _upsert_domain(self, domain: DomainNode) -> None:
        try:
            ts_first = _ts_lit(domain.first_seen)
            ts_last = _ts_lit(domain.last_seen)
            self._conn.execute(
                f"MERGE (d:Domain {{id: $id}}) "
                f"ON CREATE SET d.name = $name, "
                f"d.first_seen = timestamp('{ts_first}'), "
                f"d.last_seen = timestamp('{ts_last}'), "
                f"d.is_dga_candidate = $is_dga, d.tld = $tld "
                f"ON MATCH SET d.last_seen = timestamp('{ts_last}'), "
                f"d.is_dga_candidate = $is_dga",
                {
                    "id": domain.id,
                    "name": domain.name,
                    "is_dga": domain.is_dga_candidate,
                    "tld": domain.tld,
                },
            )
        except Exception:
            logger.debug("Failed to upsert domain %s", domain.id, exc_info=True)

    def _upsert_file(self, file_node: FileNode) -> None:
        try:
            ts_first = _ts_lit(file_node.first_seen)
            ts_last = _ts_lit(file_node.last_seen)
            self._conn.execute(
                f"MERGE (f:File {{id: $id}}) "
                f"ON CREATE SET f.path = $path, f.hash_sha256 = $hash, "
                f"f.size = $size, "
                f"f.first_seen = timestamp('{ts_first}'), "
                f"f.last_seen = timestamp('{ts_last}') "
                f"ON MATCH SET f.last_seen = timestamp('{ts_last}'), "
                f"f.hash_sha256 = CASE WHEN $hash IS NOT NULL THEN $hash ELSE f.hash_sha256 END",
                {
                    "id": file_node.id,
                    "path": file_node.path,
                    "hash": file_node.hash_sha256 or "",
                    "size": file_node.size or 0,
                },
            )
        except Exception:
            logger.debug("Failed to upsert file %s", file_node.id, exc_info=True)

    def _upsert_registry_key(self, reg: RegistryKeyNode) -> None:
        try:
            ts_first = _ts_lit(reg.first_seen)
            ts_last = _ts_lit(reg.last_seen)
            self._conn.execute(
                f"MERGE (r:RegistryKey {{id: $id}}) "
                f"ON CREATE SET r.path = $path, r.value_name = $vname, "
                f"r.value_data = $vdata, r.previous_data = $prev, "
                f"r.first_seen = timestamp('{ts_first}'), "
                f"r.last_seen = timestamp('{ts_last}') "
                f"ON MATCH SET r.last_seen = timestamp('{ts_last}'), "
                f"r.previous_data = r.value_data, r.value_data = $vdata",
                {
                    "id": reg.id,
                    "path": reg.path,
                    "vname": reg.value_name or "",
                    "vdata": reg.value_data or "",
                    "prev": reg.previous_data or "",
                },
            )
        except Exception:
            logger.debug("Failed to upsert registry key %s", reg.id, exc_info=True)

    def _create_spawned_edge(self, edge: dict) -> None:
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (u:User {{id: $user_id}}), (p:Process {{id: $process_id}}) "
                f"CREATE (u)-[:SPAWNED {{timestamp: timestamp('{ts}'), "
                f"activity_id: $activity_id, event_id: $event_id}}]->(p)",
                {
                    "user_id": edge["user_id"],
                    "process_id": edge["process_id"],
                    "activity_id": edge["activity_id"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create SPAWNED edge %s->%s",
                edge["user_id"],
                edge["process_id"],
                exc_info=True,
            )

    def _create_connected_edge(self, edge: dict) -> None:
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (p:Process {{id: $process_id}}), (ip:IP {{id: $ip_id}}) "
                f"CREATE (p)-[:CONNECTED_TO {{timestamp: timestamp('{ts}'), "
                f"dst_port: $dst_port, protocol: $protocol, "
                f"direction: $direction, event_id: $event_id}}]->(ip)",
                {
                    "process_id": edge["process_id"],
                    "ip_id": edge["ip_id"],
                    "dst_port": edge["dst_port"],
                    "protocol": edge["protocol"],
                    "direction": edge["direction"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create CONNECTED_TO edge %s->%s",
                edge["process_id"],
                edge["ip_id"],
                exc_info=True,
            )

    def _create_resolved_edge(self, edge: dict) -> None:
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (p:Process {{id: $process_id}}), (d:Domain {{id: $domain_id}}) "
                f"CREATE (p)-[:RESOLVED {{timestamp: timestamp('{ts}'), "
                f"event_id: $event_id}}]->(d)",
                {
                    "process_id": edge["process_id"],
                    "domain_id": edge["domain_id"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create RESOLVED edge %s->%s",
                edge["process_id"],
                edge["domain_id"],
                exc_info=True,
            )

    def _create_resolves_to_edge(self, edge: dict) -> None:
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (d:Domain {{id: $domain_id}}), (ip:IP {{id: $ip_id}}) "
                f"CREATE (d)-[:RESOLVES_TO {{timestamp: timestamp('{ts}'), "
                f"event_id: $event_id}}]->(ip)",
                {
                    "domain_id": edge["domain_id"],
                    "ip_id": edge["ip_id"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create RESOLVES_TO edge %s->%s",
                edge["domain_id"],
                edge["ip_id"],
                exc_info=True,
            )

    def _create_file_edge(self, edge: dict) -> None:
        op = edge["operation"]
        rel_type = {
            "CREATED": "CREATED_FILE",
            "MODIFIED": "MODIFIED_FILE",
            "READ": "READ_FILE",
            "DELETED": "DELETED_FILE",
        }.get(op, "MODIFIED_FILE")
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (p:Process {{id: $process_id}}), (f:File {{id: $file_id}}) "
                f"CREATE (p)-[:{rel_type} {{timestamp: timestamp('{ts}'), "
                f"event_id: $event_id}}]->(f)",
                {
                    "process_id": edge["process_id"],
                    "file_id": edge["file_id"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create %s edge %s->%s",
                rel_type,
                edge["process_id"],
                edge["file_id"],
                exc_info=True,
            )

    def _create_registry_edge(self, edge: dict) -> None:
        op = edge["operation"]
        rel_type = {
            "CREATED": "CREATED_REG",
            "MODIFIED": "MODIFIED_REG",
            "DELETED": "DELETED_REG",
        }.get(op, "MODIFIED_REG")
        try:
            ts = _ts_lit(edge["timestamp"])
            self._conn.execute(
                f"MATCH (p:Process {{id: $process_id}}), (r:RegistryKey {{id: $reg_id}}) "
                f"CREATE (p)-[:{rel_type} {{timestamp: timestamp('{ts}'), "
                f"event_id: $event_id}}]->(r)",
                {
                    "process_id": edge["process_id"],
                    "reg_id": edge["registry_id"],
                    "event_id": edge["event_id"],
                },
            )
        except Exception:
            logger.debug(
                "Failed to create %s edge %s->%s",
                rel_type,
                edge["process_id"],
                edge["registry_id"],
                exc_info=True,
            )

    def close(self) -> None:
        self._conn = None


def backfill_parent_pids(db: kuzu.Database) -> int:
    """One-time pass: fill parent_pid and create missing ancestor nodes.

    For each process with parent_pid=0, queries psutil for the real parent.
    Then walks the parent chain upward, creating stub Process nodes for any
    ancestors not already in the graph (e.g., shell processes that never
    generated events). This ensures the chain walker can build a full tree.

    Returns the number of processes updated or created.
    """
    import socket

    import psutil

    conn = get_connection()
    hostname = socket.gethostname()
    updated = 0

    # Collect PIDs already in the graph (streaming, not fetchall)
    existing_pids: set[int] = set()
    try:
        r = conn.execute("MATCH (p:Process) RETURN p.pid")
        while r.has_next():
            existing_pids.add(r.get_next()[0])
    except Exception:
        pass

    # Phase 1: Fix processes with parent_pid=0 (stream into list, capped at 10K)
    _MAX_BACKFILL = 10000
    try:
        result = conn.execute("MATCH (p:Process) WHERE p.parent_pid = 0 AND p.pid > 0 RETURN p.id, p.pid")
        rows = []
        while result.has_next() and len(rows) < _MAX_BACKFILL:
            rows.append(result.get_next())
    except Exception:
        logger.debug("Failed to query processes for backfill", exc_info=True)
        return 0

    def _ensure_ancestor_chain(pid: int, depth: int = 0) -> None:
        """Recursively ensure parent processes exist in the graph (max 10 deep)."""
        nonlocal updated
        if depth > 10 or pid <= 1:
            return
        try:
            p = psutil.Process(pid)
            ppid = p.ppid()
            if not ppid or ppid <= 0:
                return
            if ppid not in existing_pids:
                # Create stub node for the parent
                try:
                    parent_proc = psutil.Process(ppid)
                    name = parent_proc.name()
                    try:
                        cmdline = " ".join(parent_proc.cmdline())
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        cmdline = ""
                    try:
                        exe = parent_proc.exe()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        exe = ""
                    try:
                        create_time = datetime.fromtimestamp(parent_proc.create_time())
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        create_time = datetime.now()
                    parent_ppid = parent_proc.ppid() or 0

                    ts = _ts_lit(create_time)
                    node_id = f"{hostname}:{ppid}:{int(create_time.timestamp())}"
                    conn.execute(
                        f"MERGE (p:Process {{id: $id}}) "
                        f"ON CREATE SET p.name = $name, p.pid = $pid, "
                        f"p.cmd_line = $cmd_line, p.exe_path = $exe_path, "
                        f"p.hostname = $hostname, p.start_time = timestamp('{ts}'), "
                        f"p.parent_pid = $parent_pid",
                        {
                            "id": node_id,
                            "name": name,
                            "pid": ppid,
                            "cmd_line": cmdline,
                            "exe_path": exe,
                            "hostname": hostname,
                            "parent_pid": parent_ppid,
                        },
                    )
                    existing_pids.add(ppid)
                    updated += 1
                    logger.debug("Created stub process node: %s (PID %d)", name, ppid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    return
            # Continue walking upward
            _ensure_ancestor_chain(ppid, depth + 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return

    for node_id, pid in rows:
        try:
            p = psutil.Process(pid)
            ppid = p.ppid()
            if ppid and ppid > 0:
                conn.execute(
                    "MATCH (p:Process {id: $id}) SET p.parent_pid = $ppid",
                    {"id": node_id, "ppid": ppid},
                )
                # Also backfill cmd_line if empty
                try:
                    cmdline = p.cmdline()
                    if cmdline:
                        cmd_str = " ".join(cmdline)
                        conn.execute(
                            "MATCH (p:Process {id: $id}) "
                            "SET p.cmd_line = CASE WHEN p.cmd_line = '' THEN $cmd ELSE p.cmd_line END",
                            {"id": node_id, "cmd": cmd_str},
                        )
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                updated += 1
                # Create missing ancestor nodes
                _ensure_ancestor_chain(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            logger.debug("Failed to backfill parent_pid for %s", node_id, exc_info=True)

    # Phase 2: Create ancestor stubs for processes whose parent_pid > 0
    # but the parent PID is not in the graph
    try:
        result2 = conn.execute("MATCH (p:Process) WHERE p.parent_pid > 0 AND p.pid > 0 RETURN p.pid, p.parent_pid")
        orphans = []
        while result2.has_next():
            row = result2.get_next()
            child_pid, parent_pid = row[0], row[1]
            if parent_pid not in existing_pids:
                orphans.append(child_pid)
    except Exception:
        orphans = []

    for pid in orphans:
        _ensure_ancestor_chain(pid)

    if updated:
        logger.info("Backfilled parent_pid for %d processes (including new ancestors)", updated)
    return updated


def _ts_lit(dt: datetime | None) -> str:
    """Convert datetime to a Kuzu timestamp literal string for use in timestamp() function."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")
