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

    def register_agent(self, agent_info: dict) -> None:
        """MERGE a Host node for the agent."""
        query = """
        MERGE (h:Host {agent_id: $agent_id})
        SET h.hostname = $hostname,
            h.platform = $platform,
            h.os_version = $os_version,
            h.agent_version = $agent_version,
            h.registered_at = $registered_at,
            h.last_seen = $registered_at
        """
        with self._driver.session() as session:
            session.run(query, agent_info)
        logger.info("Registered agent %s (%s)", agent_info["agent_id"], agent_info["hostname"])

    def update_heartbeat(self, agent_id: str, timestamp: int) -> None:
        """Update Host.last_seen."""
        query = """
        MATCH (h:Host {agent_id: $agent_id})
        SET h.last_seen = $timestamp
        """
        with self._driver.session() as session:
            session.run(query, {"agent_id": agent_id, "timestamp": timestamp})

    def ingest_finding(self, agent_id: str, finding: dict) -> None:
        """Create a Finding node linked to its Host, with entity references.

        Also creates IP/Domain nodes from IOCs for cross-host correlation.
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

    def ingest_ocsf_event(self, agent_id: str, event: dict) -> None:
        """Parse an OCSF event and build cross-host graph nodes/edges.

        Creates Process, IP, and Domain nodes with host_id for lateral movement detection.
        """
        class_uid = event.get("class_uid", 0)

        # Network activity (class 4001) — key for lateral movement
        if class_uid == 4001:
            dst = event.get("dst_endpoint", {})
            dst_ip = dst.get("ip", "")
            if dst_ip:
                process = event.get("process", {})
                process_name = process.get("name", "unknown")
                query = """
                MERGE (h:Host {agent_id: $agent_id})
                MERGE (p:Process {name: $process_name, host_id: $agent_id})
                MERGE (i:IP {address: $dst_ip})
                MERGE (p)-[:CONNECTED_TO {timestamp: $timestamp}]->(i)
                MERGE (h)-[:RUNS]->(p)
                """
                with self._driver.session() as session:
                    session.run(
                        query,
                        {
                            "agent_id": agent_id,
                            "process_name": process_name,
                            "dst_ip": dst_ip,
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

    def get_fleet_status(self) -> list[dict]:
        """Query all hosts with their status and finding counts."""
        query = """
        MATCH (h:Host)
        OPTIONAL MATCH (h)-[:GENERATED]->(f:Finding)
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               h.platform AS platform,
               h.agent_version AS agent_version,
               h.last_seen AS last_seen,
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
                        "last_seen": last_seen,
                        "finding_count": record["finding_count"],
                        "status": "online" if (time.time() - last_seen) < 120 else "offline",
                    }
                )
            return agents

    def get_recent_findings(self, limit: int = 50) -> list[dict]:
        """Get recent findings across all agents."""
        query = """
        MATCH (h:Host)-[:GENERATED]->(f:Finding)
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               f.finding_id AS finding_id,
               f.timestamp AS timestamp,
               f.severity AS severity,
               f.title AS title,
               f.description AS description
        ORDER BY f.timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    def get_cross_host_connections(self, ip: str) -> list[dict]:
        """Find all hosts with processes connecting to a given IP.

        This is the core lateral movement detection query — if multiple
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

    def close(self) -> None:
        """Close the Neo4j driver."""
        self._driver.close()
