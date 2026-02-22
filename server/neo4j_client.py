"""Neo4j driver wrapper for cross-host graph operations.

Kuzu on each endpoint detects vertical chains (process ancestry, file access).
Neo4j centrally detects horizontal chains (lateral movement across hosts).
"""

from __future__ import annotations

import json
import logging
import time

from server.neo4j_schema import INIT_QUERIES

logger = logging.getLogger("server.neo4j")


class Neo4jClient:
    """Neo4j driver wrapper for fleet graph operations."""

    def __init__(self, uri: str, user: str, password: str) -> None:
        import neo4j

        self._driver = neo4j.GraphDatabase.driver(uri, auth=(user, password))
        logger.info("Connected to Neo4j at %s", uri)

    def init_schema(self) -> None:
        """Create constraints and indexes."""
        with self._driver.session() as session:
            for query in INIT_QUERIES:
                try:
                    session.run(query)
                except Exception:
                    logger.debug("Schema query skipped (may already exist): %s", query[:60])
        logger.info("Neo4j schema initialized")

    # ── Agent registration ──

    def register_agent(self, agent_info: dict, registration_key: str = "") -> None:
        """MERGE a Host node for the agent, optionally linking to a RegistrationKey."""
        query = """
        MERGE (h:Host {agent_id: $agent_id})
        SET h.hostname = $hostname,
            h.platform = $platform,
            h.os_version = $os_version,
            h.agent_version = $agent_version,
            h.ip_address = $ip_address,
            h.ip_addresses = $ip_addresses,
            h.public_ip = $public_ip,
            h.grpc_peer_ip = $grpc_peer_ip,
            h.registered_at = $registered_at,
            h.last_seen = $registered_at
        """
        # Ensure required fields are present
        if "ip_address" not in agent_info:
            agent_info["ip_address"] = ""
        if "ip_addresses" not in agent_info:
            agent_info["ip_addresses"] = []
        if "public_ip" not in agent_info:
            agent_info["public_ip"] = ""
        if "grpc_peer_ip" not in agent_info:
            agent_info["grpc_peer_ip"] = ""
        with self._driver.session() as session:
            session.run(query, agent_info)
            if registration_key:
                session.run(
                    """
                    MATCH (h:Host {agent_id: $agent_id})
                    MATCH (k:RegistrationKey {key: $key})
                    MERGE (h)-[:REGISTERED_WITH]->(k)
                    """,
                    {"agent_id": agent_info["agent_id"], "key": registration_key},
                )
        logger.info("Registered agent %s (%s)", agent_info["agent_id"], agent_info["hostname"])

    def update_heartbeat(
        self,
        agent_id: str,
        timestamp: int,
        clock_offset_ms: int = 0,
        ip_addresses: list[str] | None = None,
        public_ip: str | None = None,
    ) -> None:
        """Update Host.last_seen, clock_offset_ms, and optionally IPs."""
        # Build SET clauses dynamically to avoid overwriting with None from old agents
        set_clauses = "SET h.last_seen = $timestamp, h.clock_offset_ms = $clock_offset_ms"
        params: dict = {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "clock_offset_ms": clock_offset_ms,
        }
        if ip_addresses is not None:
            set_clauses += ", h.ip_addresses = $ip_addresses"
            params["ip_addresses"] = ip_addresses
        if public_ip is not None:
            set_clauses += ", h.public_ip = $public_ip"
            params["public_ip"] = public_ip

        # Safety: set_clauses is built entirely from trusted literals above
        # (never from user input). All values are passed as $parameters.
        query = f"""
        MATCH (h:Host {{agent_id: $agent_id}})
        {set_clauses}
        """
        with self._driver.session() as session:
            session.run(query, params)

    # ── Finding ingestion ──

    def ingest_finding(self, agent_id: str, finding: dict) -> None:
        """Create a Finding node linked to its Host, with entity references.

        Also creates IP/Domain nodes from IOCs for cross-host correlation,
        and ChainNode graph for attack chain stitching.
        """
        query = """
        MATCH (h:Host {agent_id: $agent_id})
        MERGE (f:Finding {finding_id: $finding_id})
        SET f.timestamp = $timestamp,
            f.severity = $severity,
            f.title = $title,
            f.description = $description,
            f.recommendation = $recommendation,
            f.affected_entities = $affected_entities,
            f.affected_pids = $affected_pids,
            f.iocs = $iocs_json
        MERGE (h)-[:GENERATED]->(f)
        """
        with self._driver.session() as session:
            session.run(
                query,
                {
                    "agent_id": agent_id,
                    "finding_id": finding["id"],
                    "timestamp": finding["timestamp"],
                    "severity": finding["severity"],
                    "title": finding["title"],
                    "description": finding["description"],
                    "recommendation": finding["recommendation"],
                    "affected_entities": json.dumps(finding.get("affected_entities", [])),
                    "affected_pids": json.dumps(finding.get("affected_pids", [])),
                    "iocs_json": json.dumps(finding.get("iocs", {})),
                },
            )

            # Create IOC nodes for cross-host correlation
            iocs = finding.get("iocs", {})
            for ip in iocs.get("ips", []):
                session.run(
                    """
                    MERGE (i:IP {address: $ip})
                    WITH i
                    MATCH (f:Finding {finding_id: $finding_id})
                    MERGE (f)-[:INVOLVES_IP]->(i)
                    """,
                    {"ip": ip, "finding_id": finding["id"]},
                )
            for domain in iocs.get("domains", []):
                session.run(
                    """
                    MERGE (d:Domain {name: $domain})
                    WITH d
                    MATCH (f:Finding {finding_id: $finding_id})
                    MERGE (f)-[:INVOLVES_DOMAIN]->(d)
                    """,
                    {"domain": domain, "finding_id": finding["id"]},
                )

        # Create chain nodes if chain data is present
        chain = finding.get("chain", [])
        if chain:
            self.ingest_finding_chain(agent_id, finding["id"], chain)

    def ingest_finding_chain(self, agent_id: str, finding_id: str, chain: list[dict]) -> None:
        """Create ChainNode nodes linked by NEXT relationships for a finding's chain."""
        if not chain:
            return

        with self._driver.session() as session:
            prev_node_id = None
            for idx, step in enumerate(chain):
                node_id = f"{finding_id}:{idx}"
                session.run(
                    """
                    MERGE (c:ChainNode {chain_node_id: $chain_node_id})
                    SET c.finding_id = $finding_id,
                        c.step_index = $step_index,
                        c.entity_type = $entity_type,
                        c.entity_id = $entity_id,
                        c.entity_name = $entity_name,
                        c.pid = $pid,
                        c.timestamp = $timestamp,
                        c.host_agent_id = $host_agent_id
                    WITH c
                    MATCH (f:Finding {finding_id: $finding_id})
                    MERGE (f)-[:HAS_CHAIN {step_index: $step_index}]->(c)
                    """,
                    {
                        "chain_node_id": node_id,
                        "finding_id": finding_id,
                        "step_index": idx,
                        "entity_type": step.get("entity_type", ""),
                        "entity_id": step.get("entity_id", ""),
                        "entity_name": step.get("entity_name", ""),
                        "pid": step.get("pid", 0),
                        "timestamp": step.get("timestamp", 0),
                        "host_agent_id": agent_id,
                    },
                )

                # Link to previous chain step
                if prev_node_id is not None:
                    session.run(
                        """
                        MATCH (a:ChainNode {chain_node_id: $prev_id})
                        MATCH (b:ChainNode {chain_node_id: $curr_id})
                        MERGE (a)-[:NEXT]->(b)
                        """,
                        {"prev_id": prev_node_id, "curr_id": node_id},
                    )
                prev_node_id = node_id

    # ── OCSF event ingestion ──

    def ingest_ocsf_event(self, agent_id: str, event: dict) -> None:
        """Parse an OCSF event and build cross-host graph nodes/edges.

        Creates Process, IP, and Domain nodes with host_id for lateral movement detection.
        Stores both src and dst endpoints for correlation.
        """
        class_uid = event.get("class_uid", 0)

        # Network activity (class 4001) -- key for lateral movement
        if class_uid == 4001:
            dst = event.get("dst_endpoint", {})
            src = event.get("src_endpoint", {})
            dst_ip = dst.get("ip", "")
            src_ip = src.get("ip", "")
            process = event.get("process", {})
            process_name = process.get("name", "unknown")

            if dst_ip:
                query = """
                MERGE (h:Host {agent_id: $agent_id})
                MERGE (p:Process {name: $process_name, host_id: $agent_id})
                MERGE (i:IP {address: $dst_ip})
                MERGE (p)-[:CONNECTED_TO {timestamp: $timestamp}]->(i)
                MERGE (h)-[:RUNS]->(p)
                """
                params = {
                    "agent_id": agent_id,
                    "process_name": process_name,
                    "dst_ip": dst_ip,
                    "timestamp": event.get("time", ""),
                }
                with self._driver.session() as session:
                    session.run(query, params)

                    # Also store src IP if present (for inbound correlation)
                    if src_ip:
                        session.run(
                            """
                            MERGE (si:IP {address: $src_ip})
                            WITH si
                            MATCH (p:Process {name: $process_name, host_id: $agent_id})
                            MERGE (si)-[:SOURCE_OF {timestamp: $timestamp}]->(p)
                            """,
                            {
                                "src_ip": src_ip,
                                "process_name": process_name,
                                "agent_id": agent_id,
                                "timestamp": event.get("time", ""),
                            },
                        )

        # DNS activity (class 4003)
        elif class_uid == 4003:
            domain = event.get("query_domain", "")
            if domain:
                query = """
                MERGE (h:Host {agent_id: $agent_id})
                MERGE (d:Domain {name: $domain})
                MERGE (h)-[:RESOLVED {timestamp: $timestamp}]->(d)
                """
                with self._driver.session() as session:
                    session.run(
                        query,
                        {
                            "agent_id": agent_id,
                            "domain": domain,
                            "timestamp": event.get("time", ""),
                        },
                    )

    # ── Lateral movement detection ──

    def detect_lateral_movements(self, limit: int = 50) -> list[dict]:
        """Detect lateral movement: a finding on one host mentions an IP
        that belongs to a different monitored host (via Host.ip_addresses).

        Two detection paths (UNION):
        1. Chain-based: finding chain contains an IP step matching another host
        2. IOC-based: finding INVOLVES_IP an address belonging to another host
        """
        query = """
        CALL {
            MATCH (victim:Host)-[:GENERATED]->(f:Finding)-[:HAS_CHAIN]->(step:ChainNode)
            WHERE step.entity_type = 'ip'
            MATCH (source:Host)
            WHERE source.agent_id <> victim.agent_id
              AND step.entity_id IN source.ip_addresses
            RETURN source.agent_id AS src_agent_id,
                   source.hostname AS src_hostname,
                   victim.agent_id AS dst_agent_id,
                   victim.hostname AS dst_hostname,
                   f.finding_id AS dst_finding_id,
                   f.title AS dst_finding_title,
                   f.severity AS dst_severity,
                   f.timestamp AS dst_timestamp,
                   step.entity_id AS pivot_ip
            ORDER BY dst_timestamp DESC
            LIMIT $limit
            UNION
            MATCH (victim:Host)-[:GENERATED]->(f:Finding)-[:INVOLVES_IP]->(ip:IP)
            MATCH (source:Host)
            WHERE source.agent_id <> victim.agent_id
              AND ip.address IN source.ip_addresses
            RETURN source.agent_id AS src_agent_id,
                   source.hostname AS src_hostname,
                   victim.agent_id AS dst_agent_id,
                   victim.hostname AS dst_hostname,
                   f.finding_id AS dst_finding_id,
                   f.title AS dst_finding_title,
                   f.severity AS dst_severity,
                   f.timestamp AS dst_timestamp,
                   ip.address AS pivot_ip
            ORDER BY dst_timestamp DESC
            LIMIT $limit
        }
        RETURN src_agent_id, src_hostname, dst_agent_id, dst_hostname,
               dst_finding_id, dst_finding_title, dst_severity, dst_timestamp, pivot_ip
        ORDER BY dst_timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    def get_lateral_movement_detail(self, finding_id: str) -> dict:
        """Get finding chain detail with source host identified by pivot IP."""
        query = """
        MATCH (victim:Host)-[:GENERATED]->(f:Finding {finding_id: $finding_id})
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(c:ChainNode)
        WITH victim, f, c ORDER BY c.step_index
        WITH victim, f, collect({
            entity_type: c.entity_type,
            entity_id: c.entity_id,
            entity_name: c.entity_name,
            pid: c.pid,
            timestamp: c.timestamp,
            step_index: c.step_index
        }) AS chain
        // Find source host: chain IP or IOC IP that belongs to another host
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(step:ChainNode)
        WHERE step.entity_type = 'ip'
        OPTIONAL MATCH (src1:Host)
        WHERE src1.agent_id <> victim.agent_id
          AND step.entity_id IN src1.ip_addresses
        OPTIONAL MATCH (f)-[:INVOLVES_IP]->(ip:IP)
        OPTIONAL MATCH (src2:Host)
        WHERE src2.agent_id <> victim.agent_id
          AND ip.address IN src2.ip_addresses
        WITH victim, f, chain,
             coalesce(src1, src2) AS source
        RETURN victim.agent_id AS dst_agent_id,
               victim.hostname AS dst_hostname,
               f.finding_id AS finding_id,
               f.title AS title,
               f.severity AS severity,
               f.timestamp AS timestamp,
               chain,
               source.agent_id AS src_agent_id,
               source.hostname AS src_hostname
        LIMIT 1
        """
        with self._driver.session() as session:
            result = session.run(query, {"finding_id": finding_id})
            record = result.single()
            if record:
                return dict(record)
            return {}

    def detect_vertical_movements(self, limit: int = 50) -> list[dict]:
        """Detect privilege escalation within single-agent chains.

        Looks for chains where a user context changes (e.g., non-root -> root).
        """
        query = """
        MATCH (h:Host)-[:GENERATED]->(f:Finding)-[:HAS_CHAIN]->(c1:ChainNode)
        WHERE c1.entity_type = 'user'
        MATCH (f)-[:HAS_CHAIN]->(c2:ChainNode)
        WHERE c2.entity_type = 'user'
          AND c2.step_index > c1.step_index
          AND c2.entity_id <> c1.entity_id
          AND (c2.entity_name = 'root' OR c2.entity_id = '0')
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               f.finding_id AS finding_id,
               f.title AS title,
               f.severity AS severity,
               f.timestamp AS timestamp,
               c1.entity_name AS original_user,
               c2.entity_name AS escalated_user,
               c1.step_index AS original_step,
               c2.step_index AS escalated_step
        ORDER BY f.timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    def get_host_to_host_connections(self, limit: int = 100) -> list[dict]:
        """Get inter-host connections by matching chain/IOC IPs to other hosts' ip_addresses."""
        query = """
        CALL {
            MATCH (hA:Host)-[:GENERATED]->(f:Finding)-[:HAS_CHAIN]->(step:ChainNode)
            WHERE step.entity_type = 'ip'
            MATCH (hB:Host)
            WHERE hA.agent_id <> hB.agent_id
              AND step.entity_id IN hB.ip_addresses
            RETURN DISTINCT hA.agent_id AS src_agent_id,
                   hA.hostname AS src_hostname,
                   hB.agent_id AS dst_agent_id,
                   hB.hostname AS dst_hostname,
                   step.entity_id AS shared_ip
            LIMIT $limit
            UNION
            MATCH (hA:Host)-[:GENERATED]->(f:Finding)-[:INVOLVES_IP]->(ip:IP)
            MATCH (hB:Host)
            WHERE hA.agent_id <> hB.agent_id
              AND ip.address IN hB.ip_addresses
            RETURN DISTINCT hA.agent_id AS src_agent_id,
                   hA.hostname AS src_hostname,
                   hB.agent_id AS dst_agent_id,
                   hB.hostname AS dst_hostname,
                   ip.address AS shared_ip
            LIMIT $limit
        }
        RETURN src_agent_id, src_hostname, dst_agent_id, dst_hostname, shared_ip
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    # ── Agent detail queries ──

    def get_agent_detail(self, agent_id: str) -> dict | None:
        """Get host info + finding counts by severity for a specific agent."""
        query = """
        MATCH (h:Host {agent_id: $agent_id})
        OPTIONAL MATCH (h)-[:GENERATED]->(f:Finding)
        WITH h,
             count(f) AS total_findings,
             sum(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
             sum(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count,
             sum(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium_count,
             sum(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low_count,
             sum(CASE WHEN f.severity = 'info' THEN 1 ELSE 0 END) AS info_count
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               h.platform AS platform,
               h.os_version AS os_version,
               h.agent_version AS agent_version,
               h.ip_address AS ip_address,
               h.ip_addresses AS ip_addresses,
               h.public_ip AS public_ip,
               h.grpc_peer_ip AS grpc_peer_ip,
               h.registered_at AS registered_at,
               h.last_seen AS last_seen,
               h.clock_offset_ms AS clock_offset_ms,
               total_findings,
               critical_count,
               high_count,
               medium_count,
               low_count,
               info_count
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id})
            record = result.single()
            if record:
                data = dict(record)
                last_seen = data.get("last_seen") or 0
                data["status"] = "online" if (time.time() - last_seen) < 120 else "offline"
                return data
            return None

    def get_agent_findings(self, agent_id: str, limit: int = 100) -> list[dict]:
        """Get findings for a specific agent, with chain step counts."""
        query = """
        MATCH (h:Host {agent_id: $agent_id})-[:GENERATED]->(f:Finding)
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(c:ChainNode)
        WITH f, count(c) AS chain_length
        RETURN f.finding_id AS finding_id,
               f.timestamp AS timestamp,
               f.severity AS severity,
               f.title AS title,
               f.description AS description,
               f.recommendation AS recommendation,
               f.affected_entities AS affected_entities,
               f.affected_pids AS affected_pids,
               f.iocs AS iocs,
               chain_length
        ORDER BY f.timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id, "limit": limit})
            return [dict(record) for record in result]

    def get_agent_chain_steps(self, agent_id: str, limit: int = 200) -> list[dict]:
        """Get chain steps for all findings belonging to an agent."""
        query = """
        MATCH (c:ChainNode {host_agent_id: $agent_id})
        RETURN c.chain_node_id AS chain_node_id,
               c.finding_id AS finding_id,
               c.step_index AS step_index,
               c.entity_type AS entity_type,
               c.entity_id AS entity_id,
               c.entity_name AS entity_name,
               c.pid AS pid,
               c.timestamp AS timestamp
        ORDER BY c.finding_id, c.step_index
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id, "limit": limit})
            return [dict(record) for record in result]

    # ── Fleet overview ──

    def get_fleet_status(self) -> list[dict]:
        """Query all hosts with their status and finding counts."""
        query = """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:GENERATED]->(f:Finding)
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               h.platform AS platform,
               h.agent_version AS agent_version,
               h.ip_address AS ip_address,
               h.ip_addresses AS ip_addresses,
               h.public_ip AS public_ip,
               h.grpc_peer_ip AS grpc_peer_ip,
               h.last_seen AS last_seen,
               h.clock_offset_ms AS clock_offset_ms,
               count(f) AS finding_count
        ORDER BY h.last_seen DESC
        """
        with self._driver.session() as session:
            result = session.run(query)
            agents = []
            for record in result:
                last_seen = record["last_seen"] or 0
                agents.append(
                    {
                        "agent_id": record["agent_id"],
                        "hostname": record["hostname"],
                        "platform": record["platform"],
                        "agent_version": record["agent_version"],
                        "ip_address": record["ip_address"],
                        "ip_addresses": record["ip_addresses"] or [],
                        "public_ip": record["public_ip"] or "",
                        "grpc_peer_ip": record["grpc_peer_ip"] or "",
                        "last_seen": last_seen,
                        "clock_offset_ms": record["clock_offset_ms"],
                        "finding_count": record["finding_count"],
                        "status": "online" if (time.time() - last_seen) < 120 else "offline",
                    }
                )
            return agents

    def get_recent_findings(self, limit: int = 50) -> list[dict]:
        """Get recent findings across all agents, with chain step counts."""
        query = """
        MATCH (h:Host)-[:GENERATED]->(f:Finding)
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(c:ChainNode)
        WITH h, f, count(c) AS chain_length
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               f.finding_id AS finding_id,
               f.timestamp AS timestamp,
               f.severity AS severity,
               f.title AS title,
               f.description AS description,
               chain_length
        ORDER BY f.timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    def get_finding_detail(self, finding_id: str) -> dict | None:
        """Get a single finding with full chain data."""
        query = """
        MATCH (h:Host)-[:GENERATED]->(f:Finding {finding_id: $finding_id})
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(c:ChainNode)
        WITH h, f, c ORDER BY c.step_index
        WITH h, f, collect({
            entity_type: c.entity_type,
            entity_id: c.entity_id,
            entity_name: c.entity_name,
            pid: c.pid,
            timestamp: c.timestamp,
            step_index: c.step_index
        }) AS chain
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               f.finding_id AS finding_id,
               f.timestamp AS timestamp,
               f.severity AS severity,
               f.title AS title,
               f.description AS description,
               f.recommendation AS recommendation,
               f.affected_entities AS affected_entities,
               f.affected_pids AS affected_pids,
               f.iocs AS iocs,
               chain
        """
        with self._driver.session() as session:
            result = session.run(query, {"finding_id": finding_id})
            record = result.single()
            if record:
                return dict(record)
            return None

    def get_cross_host_connections(self, ip: str) -> list[dict]:
        """Find all hosts with processes connecting to a given IP.

        This is the core lateral movement detection query -- if multiple
        hosts connect to the same suspicious IP, it may indicate C2 or
        lateral movement.
        """
        query = """
        MATCH (h:Host)-[:RUNS]->(p:Process)-[:CONNECTED_TO]->(i:IP {address: $ip})
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               p.name AS process_name,
               collect(p.host_id) AS host_ids
        """
        with self._driver.session() as session:
            result = session.run(query, {"ip": ip})
            return [dict(record) for record in result]

    # ── Dashboard user management ──

    def create_dashboard_user(self, username: str, password_hash: str, role: str = "admin") -> None:
        """Create a dashboard user for SOC authentication."""
        query = """
        MERGE (u:DashboardUser {username: $username})
        SET u.password_hash = $password_hash,
            u.role = $role,
            u.created_at = $created_at
        """
        with self._driver.session() as session:
            session.run(
                query,
                {
                    "username": username,
                    "password_hash": password_hash,
                    "role": role,
                    "created_at": int(time.time()),
                },
            )

    def verify_dashboard_user(self, username: str) -> dict | None:
        """Look up a dashboard user by username."""
        query = """
        MATCH (u:DashboardUser {username: $username})
        RETURN u.username AS username,
               u.password_hash AS password_hash,
               u.role AS role
        """
        with self._driver.session() as session:
            result = session.run(query, {"username": username})
            record = result.single()
            if record:
                return dict(record)
            return None

    def count_dashboard_users(self) -> int:
        """Count dashboard users (for bootstrap check)."""
        query = "MATCH (u:DashboardUser) RETURN count(u) AS cnt"
        with self._driver.session() as session:
            result = session.run(query)
            record = result.single()
            return record["cnt"] if record else 0

    # ── Registration key management ──

    def create_registration_key(
        self,
        key: str,
        label: str,
        created_by: str,
        expires_at: int | None = None,
        max_uses: int | None = None,
    ) -> dict:
        """Create a new registration key."""
        query = """
        CREATE (k:RegistrationKey {
            key: $key,
            label: $label,
            created_at: $created_at,
            created_by: $created_by,
            expires_at: $expires_at,
            max_uses: $max_uses,
            use_count: 0,
            revoked: false,
            revoked_at: null,
            revoked_by: null
        })
        RETURN k.key AS key, k.label AS label, k.created_at AS created_at,
               k.created_by AS created_by, k.expires_at AS expires_at,
               k.max_uses AS max_uses, k.use_count AS use_count,
               k.revoked AS revoked
        """
        with self._driver.session() as session:
            result = session.run(
                query,
                {
                    "key": key,
                    "label": label,
                    "created_at": int(time.time()),
                    "created_by": created_by,
                    "expires_at": expires_at,
                    "max_uses": max_uses,
                },
            )
            record = result.single()
            return dict(record) if record else {}

    def list_registration_keys(self) -> list[dict]:
        """List all registration keys, ordered by created_at desc."""
        query = """
        MATCH (k:RegistrationKey)
        OPTIONAL MATCH (h:Host)-[:REGISTERED_WITH]->(k)
        WITH k, count(h) AS host_count
        RETURN k.key AS key, k.label AS label, k.created_at AS created_at,
               k.created_by AS created_by, k.expires_at AS expires_at,
               k.max_uses AS max_uses, k.use_count AS use_count,
               k.revoked AS revoked, k.revoked_at AS revoked_at,
               k.revoked_by AS revoked_by, host_count
        ORDER BY k.created_at DESC
        """
        with self._driver.session() as session:
            result = session.run(query)
            keys = []
            now = int(time.time())
            for record in result:
                d = dict(record)
                # Compute status
                if d["revoked"]:
                    d["status"] = "revoked"
                elif d["expires_at"] and d["expires_at"] < now:
                    d["status"] = "expired"
                elif d["max_uses"] and d["use_count"] >= d["max_uses"]:
                    d["status"] = "exhausted"
                else:
                    d["status"] = "active"
                keys.append(d)
            return keys

    def revoke_registration_key(self, key: str, revoked_by: str) -> bool:
        """Revoke a registration key. Returns True if found and revoked."""
        query = """
        MATCH (k:RegistrationKey {key: $key})
        SET k.revoked = true,
            k.revoked_at = $revoked_at,
            k.revoked_by = $revoked_by
        RETURN k.key AS key
        """
        with self._driver.session() as session:
            result = session.run(
                query,
                {
                    "key": key,
                    "revoked_at": int(time.time()),
                    "revoked_by": revoked_by,
                },
            )
            return result.single() is not None

    def delete_registration_key(self, key: str) -> bool:
        """Permanently delete a registration key. Returns True if found and deleted."""
        query = """
        MATCH (k:RegistrationKey {key: $key})
        DETACH DELETE k
        RETURN count(*) AS deleted
        """
        with self._driver.session() as session:
            result = session.run(query, {"key": key})
            record = result.single()
            return record and record["deleted"] > 0

    def validate_registration_key(self, key: str) -> tuple[bool, str]:
        """Validate a registration key and atomically increment use_count.

        Returns (valid, reason). On success, use_count is incremented.
        """
        with self._driver.session() as session:
            # Fetch the key
            result = session.run(
                "MATCH (k:RegistrationKey {key: $key}) RETURN k",
                {"key": key},
            )
            record = result.single()
            if not record:
                return False, "invalid_key"

            node = record["k"]
            if node["revoked"]:
                return False, "key_revoked"

            now = int(time.time())
            if node["expires_at"] is not None and node["expires_at"] < now:
                return False, "key_expired"

            if node["max_uses"] is not None and node["use_count"] >= node["max_uses"]:
                return False, "max_uses_exceeded"

            # Increment use_count
            session.run(
                "MATCH (k:RegistrationKey {key: $key}) SET k.use_count = k.use_count + 1",
                {"key": key},
            )
            return True, "ok"

    def close(self) -> None:
        """Close the Neo4j driver."""
        self._driver.close()
