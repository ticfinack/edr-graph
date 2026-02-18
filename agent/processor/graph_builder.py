"""Upsert nodes and create edges in Kuzu graph database."""

from __future__ import annotations

import logging
from datetime import datetime

import kuzu

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


class GraphBuilder:
    """Writes extracted entities into the Kuzu graph.

    Each instance holds its own kuzu.Connection (thread-local usage).
    """

    def __init__(self, db: kuzu.Database) -> None:
        self._db = db
        self._conn = kuzu.Connection(db)

    def write_entities(self, entities: ExtractedEntities) -> None:
        """Upsert all nodes and create all edges from extracted entities."""
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
                if existing is None or u.last_seen > existing.last_seen:
                    users[u.id] = u
            for p in entities.processes:
                processes[p.id] = p  # last write wins (same data)
            for ip in entities.ips:
                existing = ips.get(ip.id)
                if existing is None or ip.last_seen > existing.last_seen:
                    ips[ip.id] = ip
            for d in entities.domains:
                existing = domains.get(d.id)
                if existing is None or d.last_seen > existing.last_seen:
                    domains[d.id] = d
            for f in entities.files:
                existing = files.get(f.id)
                if existing is None or f.last_seen > existing.last_seen:
                    files[f.id] = f
            for r in entities.registry_keys:
                existing = registry_keys.get(r.id)
                if existing is None or r.last_seen > existing.last_seen:
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
                f"p.bundle_id = $bundle_id, p.code_signed = $code_signed, "
                f"p.signing_authority = $signing_authority "
                f"ON MATCH SET p.bundle_id = CASE WHEN $bundle_id <> '' THEN $bundle_id ELSE p.bundle_id END, "
                f"p.code_signed = CASE WHEN $code_signed IS NOT NULL THEN $code_signed ELSE p.code_signed END, "
                f"p.signing_authority = CASE WHEN $signing_authority <> '' THEN $signing_authority ELSE p.signing_authority END",
                {
                    "id": proc.id,
                    "name": proc.name,
                    "pid": proc.pid,
                    "cmd_line": proc.cmd_line or "",
                    "exe_path": proc.exe_path or "",
                    "hostname": proc.hostname,
                    "bundle_id": proc.bundle_id or "",
                    "code_signed": proc.code_signed,
                    "signing_authority": proc.signing_authority or "",
                },
            )
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
                f"ip.last_seen = timestamp('{ts_last}') "
                f"ON MATCH SET ip.last_seen = timestamp('{ts_last}')",
                {
                    "id": ip_node.id,
                    "address": ip_node.address,
                    "is_private": ip_node.is_private,
                },
            )
        except Exception:
            logger.debug("Failed to upsert IP %s", ip_node.id, exc_info=True)

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


def _ts_lit(dt: datetime | None) -> str:
    """Convert datetime to a Kuzu timestamp literal string for use in timestamp() function."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")
