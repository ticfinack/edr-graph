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


def _build_chain_from_xdr_records(
    records: list[dict], *, reverse: bool = False,
) -> list[dict]:
    """Build a chain from federated XDR query results.

    Natural order (reverse=False): USER → PROCESS(es) → IP
        Used for source chains (outbound — shows who initiated).
    Reversed order (reverse=True): IP → PROCESS(es) → USER
        Used for target chains (inbound — flow enters from pivot IP).

    Processes are deduplicated by PID and always in causal order
    (timestamp ASC — parent processes before child processes).
    """
    # ── Extract user ──
    username = ""
    for rec in records:
        if rec.get("username") and rec["username"] != "None":
            username = rec["username"]
            break
    user_step = {"entity_type": "user", "entity_id": username or "unknown",
                 "entity_name": username or "unknown", "pid": 0,
                 "username": username, "timestamp": 0}

    # ── Extract unique processes, dedup by PID ──
    seen_pids: set[int] = set()
    proc_steps: list[dict] = []
    for rec in records:
        p = rec.get("process_name")
        pid = rec.get("pid")
        if p and pid and pid not in seen_pids:
            seen_pids.add(pid)
            ts = rec.get("timestamp") or 0
            try:
                ts = float(ts)
            except (ValueError, TypeError):
                ts = 0
            proc_steps.append({
                "entity_type": "process", "entity_id": p,
                "entity_name": p, "pid": pid,
                "cmd_line": rec.get("cmd_line", ""),
                "username": rec.get("username", ""),
                "timestamp": ts,
            })
    # Always sort processes in causal order (oldest/parent first)
    proc_steps.sort(key=lambda s: s["timestamp"])

    # ── Extract remote IP ──
    ip_step = None
    for rec in records:
        if rec.get("from_ip"):
            ip_step = {"entity_type": "ip", "entity_id": rec["from_ip"],
                       "entity_name": rec["from_ip"], "pid": 0, "timestamp": 0}
            break

    # ── Assemble chain ──
    if reverse:
        # Target chain: IP → authenticating_process → USER → child processes
        # The USER step goes after the first process that established the
        # identity (e.g. sshd authenticates as root BEFORE spawning bash).
        steps = []
        if ip_step:
            steps.append(ip_step)
        inserted_user = False
        for ps in proc_steps:
            steps.append(ps)
            if not inserted_user and ps.get("username") == username and username:
                steps.append(user_step)
                inserted_user = True
        if not inserted_user:
            steps.append(user_step)
    else:
        # Source chain: USER → processes (causal order) → IP
        steps = [user_step]
        steps.extend(proc_steps)
        if ip_step:
            steps.append(ip_step)

    # Assign step_index
    for i, step in enumerate(steps):
        step["step_index"] = i
    return steps


def _build_chain_from_ocsf_evidence(
    ocsf_rows: list[dict],
    target_agent_id: str,
    pivot_ips: list[str],
) -> list[dict] | None:
    """Build a target chain from OCSF ledger evidence.

    Fallback when lateral_victim_trace returns empty — reconstructs
    the target-side process chain from raw Authentication, NetworkActivity,
    and ProcessActivity events stored in incident_ocsf_evidence.

    Temporal guardrails prevent PID-reuse collisions:
    - Events are processed in chronological order (timestamp ASC)
    - Anchor events set a time floor; child processes must occur after
    - Parent-child relationships are validated temporally (child >= parent)

    Returns chain in target order: IP → PROCESS(es) → USER, or None.
    """
    if not ocsf_rows or not pivot_ips:
        return None

    pivot_set = set(pivot_ips)

    # ── 1. Filter to target agent, parse JSON, sort chronologically ──
    target_events: list[dict] = []
    for row in ocsf_rows:
        if row.get("agent_id") != target_agent_id:
            continue
        try:
            evt = json.loads(row["ocsf_json"])
            evt["_event_type"] = row.get("event_type", "")
            evt["_timestamp"] = float(row.get("timestamp", 0) or 0)
            target_events.append(evt)
        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    if not target_events:
        return None

    # TEMPORAL GUARDRAIL #1: chronological sort (oldest first)
    target_events.sort(key=lambda e: e["_timestamp"])

    # ── 2. Find anchor events: Auth/Net with src_endpoint.ip matching pivot ──
    anchor_pids: dict[int, float] = {}   # pid → timestamp
    anchor_pid_users: dict[int, str] = {}  # pid → username (from auth events)
    anchor_user = ""
    anchor_ip = ""
    anchor_ts: float = 0.0               # time floor for children

    for evt in target_events:
        etype = evt.get("_event_type", "")
        src_ip = (evt.get("src_endpoint") or {}).get("ip", "")

        if src_ip not in pivot_set:
            continue

        if not anchor_ip:
            anchor_ip = src_ip

        auth_username = ""
        if etype in ("Authentication", "authentication"):
            auth_username = (evt.get("user") or {}).get("name", "")
            if auth_username and not anchor_user:
                anchor_user = auth_username

        if etype in ("Authentication", "authentication",
                     "NetworkActivity", "network_activity"):
            proc = evt.get("process") or {}
            pid = proc.get("pid")
            evt_ts = evt["_timestamp"]
            if pid and isinstance(pid, int) and pid > 0:
                anchor_pids[pid] = evt_ts
                if auth_username:
                    anchor_pid_users[pid] = auth_username
                # Record earliest anchor time
                if anchor_ts == 0.0 or evt_ts < anchor_ts:
                    anchor_ts = evt_ts

    if not anchor_pids and not anchor_user:
        return None

    # ── 3. Walk ProcessActivity for child processes (temporally bounded) ──
    # proc_map: pid → {pid, name, cmd_line, timestamp, username}
    proc_map: dict[int, dict] = {}

    # Seed with anchor processes
    for evt in target_events:
        proc = evt.get("process") or {}
        pid = proc.get("pid")
        if pid and isinstance(pid, int) and pid in anchor_pids and pid not in proc_map:
                proc_map[pid] = {
                    "pid": pid,
                    "name": proc.get("name", ""),
                    "cmd_line": proc.get("cmd_line", ""),
                    "timestamp": anchor_pids[pid],
                    "username": anchor_pid_users.get(pid, ""),
                }

    # known_pids maps pid → timestamp (for temporal parent-child validation)
    known_pids: dict[int, float] = dict(anchor_pids)

    # Iterate chronologically-sorted events; single pass suffices because
    # events are already in time order — a parent always appears before
    # its children.
    for evt in target_events:
        etype = evt.get("_event_type", "")
        if etype not in ("ProcessActivity", "process_activity"):
            continue
        proc = evt.get("process") or {}
        pid = proc.get("pid")
        ppid = proc.get("parent_pid")
        evt_ts = evt["_timestamp"]

        if not (pid and isinstance(pid, int) and pid > 0):
            continue
        if ppid not in known_pids:
            continue
        if pid in known_pids:
            continue

        parent_ts = known_pids[ppid]

        # TEMPORAL GUARDRAIL #2: child must occur at or after anchor
        if evt_ts < anchor_ts:
            continue
        # TEMPORAL GUARDRAIL #3: child must occur at or after parent
        if evt_ts < parent_ts:
            continue

        known_pids[pid] = evt_ts
        proc_map[pid] = {
            "pid": pid,
            "name": proc.get("name", ""),
            "cmd_line": proc.get("cmd_line", ""),
            "timestamp": evt_ts,
            "username": "",
        }
        try:
            uname = evt.get("actor", {}).get("user", {}).get("name", "")
            if uname:
                proc_map[pid]["username"] = uname
                if not anchor_user:
                    anchor_user = uname
        except AttributeError:
            pass

    # ── 4. Build chain: IP → processes (causal order) → USER ──
    steps: list[dict] = []

    # IP step
    ip_addr = anchor_ip or (pivot_ips[0] if pivot_ips else "")
    if ip_addr:
        steps.append({
            "entity_type": "ip", "entity_id": ip_addr,
            "entity_name": ip_addr, "pid": 0, "timestamp": 0,
        })

    # Process steps sorted by timestamp (parent before child)
    proc_steps = sorted(proc_map.values(), key=lambda p: p["timestamp"])
    inserted_user = False
    for ps in proc_steps:
        steps.append({
            "entity_type": "process",
            "entity_id": ps.get("name", ""),
            "entity_name": ps.get("name", ""),
            "pid": ps["pid"],
            "cmd_line": ps.get("cmd_line", ""),
            "timestamp": ps["timestamp"],
        })
        if not inserted_user and anchor_user and ps.get("username") == anchor_user:
            steps.append({
                "entity_type": "user", "entity_id": anchor_user,
                "entity_name": anchor_user, "pid": 0, "timestamp": 0,
            })
            inserted_user = True

    if not inserted_user and anchor_user:
        steps.append({
            "entity_type": "user", "entity_id": anchor_user,
            "entity_name": anchor_user, "pid": 0, "timestamp": 0,
        })

    if len(steps) <= 1:
        return None

    for i, step in enumerate(steps):
        step["step_index"] = i

    return steps


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
        ioc_stats_json: str | None = None,
    ) -> None:
        """Update Host.last_seen, clock_offset_ms, and optionally IPs/IOC stats."""
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
        if ioc_stats_json is not None:
            set_clauses += ", h.ioc_stats_json = $ioc_stats_json"
            params["ioc_stats_json"] = ioc_stats_json

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

        Naming convention (attack-direction semantics):
        - src = the host that generated the finding (initiated the movement)
        - dst = the host whose IP was found in the finding (target of movement)

        Two detection paths (UNION):
        1. Chain-based: finding chain contains an IP step matching another host
        2. IOC-based: finding INVOLVES_IP an address belonging to another host
        """
        query = """
        CALL {
            MATCH (initiator:Host)-[:GENERATED]->(f:Finding)-[:HAS_CHAIN]->(step:ChainNode)
            WHERE step.entity_type = 'ip'
            MATCH (target:Host)
            WHERE target.agent_id <> initiator.agent_id
              AND step.entity_id IN target.ip_addresses
            RETURN initiator.agent_id AS src_agent_id,
                   initiator.hostname AS src_hostname,
                   target.agent_id AS dst_agent_id,
                   target.hostname AS dst_hostname,
                   f.finding_id AS src_finding_id,
                   f.title AS src_finding_title,
                   f.severity AS src_severity,
                   f.timestamp AS src_timestamp,
                   step.entity_id AS pivot_ip
            ORDER BY src_timestamp DESC
            LIMIT $limit
            UNION
            MATCH (initiator:Host)-[:GENERATED]->(f:Finding)-[:INVOLVES_IP]->(ip:IP)
            MATCH (target:Host)
            WHERE target.agent_id <> initiator.agent_id
              AND ip.address IN target.ip_addresses
            RETURN initiator.agent_id AS src_agent_id,
                   initiator.hostname AS src_hostname,
                   target.agent_id AS dst_agent_id,
                   target.hostname AS dst_hostname,
                   f.finding_id AS src_finding_id,
                   f.title AS src_finding_title,
                   f.severity AS src_severity,
                   f.timestamp AS src_timestamp,
                   ip.address AS pivot_ip
            ORDER BY src_timestamp DESC
            LIMIT $limit
        }
        RETURN src_agent_id, src_hostname, dst_agent_id, dst_hostname,
               src_finding_id, src_finding_title, src_severity, src_timestamp, pivot_ip
        ORDER BY src_timestamp DESC
        LIMIT $limit
        """
        with self._driver.session() as session:
            result = session.run(query, {"limit": limit})
            return [dict(record) for record in result]

    def get_lateral_movement_detail(self, finding_id: str, settings_db=None) -> dict:
        """Get XDR attack graph detail for a lateral movement finding.

        Naming convention (attack-direction semantics):
        - src = finding host (initiated the movement, e.g. SSH client)
        - dst = IP-match host (target of movement, e.g. SSH server)
        - source_chain = what happened on the source (finding's chain)
        - target_chain = what happened on the target (XDR-stitched)

        4-phase approach:
        Phase 0: Check for persisted Incident with stitched chains (instant)
        Phase 1: Finding + chain + pivot IP + target host identification
        Phase 2A: Target chain from target host's findings in Neo4j
        Phase 2B: Federated XDR → lateral_victim_trace on TARGET (inbound)
        Phase 2C: Federated XDR → lateral_source_trace on SOURCE (outbound)
        """
        with self._driver.session() as session:
            # ── Phase 0: Check for persisted Incident chains ──
            # Use the FINDING's own chain as source_chain (per-finding),
            # fall back to incident-level HAS_SOURCE_CHAIN only if finding has none.
            # Always use the incident's HAS_TARGET_CHAIN for the target side.
            phase0_query = """
            MATCH (inc:Incident)-[:SOURCE_FINDING]->(f:Finding {finding_id: $finding_id})
            // Per-finding chain (specific to this finding)
            OPTIONAL MATCH (f)-[:HAS_CHAIN]->(fc:ChainNode)
            WITH inc, f, fc ORDER BY fc.step_index
            WITH inc, f, collect(CASE WHEN fc IS NOT NULL THEN {
                entity_type: fc.entity_type, entity_id: fc.entity_id,
                entity_name: fc.entity_name, pid: fc.pid,
                timestamp: fc.timestamp, step_index: fc.step_index
            } END) AS finding_chain_raw
            // Incident-level source chain (fallback)
            OPTIONAL MATCH (inc)-[:HAS_SOURCE_CHAIN]->(sc:ChainNode)
            WITH inc, f, finding_chain_raw, sc ORDER BY sc.step_index
            WITH inc, f, finding_chain_raw, collect(CASE WHEN sc IS NOT NULL THEN {
                entity_type: sc.entity_type, entity_id: sc.entity_id,
                entity_name: sc.entity_name, pid: sc.pid,
                timestamp: sc.timestamp, step_index: sc.step_index
            } END) AS incident_source_raw
            // Incident-level target chain
            OPTIONAL MATCH (inc)-[:HAS_TARGET_CHAIN]->(tc:ChainNode)
            WITH inc, f, finding_chain_raw, incident_source_raw, tc ORDER BY tc.step_index
            WITH inc, f, finding_chain_raw, incident_source_raw, collect(CASE WHEN tc IS NOT NULL THEN {
                entity_type: tc.entity_type, entity_id: tc.entity_id,
                entity_name: tc.entity_name, pid: tc.pid,
                timestamp: tc.timestamp, step_index: tc.step_index
            } END) AS target_chain_raw
            WITH inc, f,
                 [s IN finding_chain_raw WHERE s IS NOT NULL] AS finding_chain,
                 [s IN incident_source_raw WHERE s IS NOT NULL] AS incident_source,
                 [t IN target_chain_raw WHERE t IS NOT NULL] AS target_chain
            WHERE size(finding_chain) > 0 OR size(incident_source) > 0 OR size(target_chain) > 0
            OPTIONAL MATCH (src:Host {agent_id: inc.src_agent_id})
            OPTIONAL MATCH (dst:Host {agent_id: inc.dst_agent_id})
            OPTIONAL MATCH (h:Host)-[:GENERATED]->(f)
            RETURN inc.incident_id AS incident_id,
                   inc.src_agent_id AS src_agent_id,
                   COALESCE(src.hostname, h.hostname) AS src_hostname,
                   inc.dst_agent_id AS dst_agent_id,
                   dst.hostname AS dst_hostname,
                   inc.pivot_ip AS pivot_ip,
                   f.finding_id AS finding_id,
                   f.title AS title,
                   f.severity AS severity,
                   f.timestamp AS timestamp,
                   f.description AS description,
                   // Prefer finding's own chain; fall back to incident source chain
                   CASE WHEN size(finding_chain) > 0 THEN finding_chain
                        ELSE incident_source END AS source_chain,
                   target_chain
            LIMIT 1
            """
            p0_result = session.run(phase0_query, {"finding_id": finding_id})
            p0_record = p0_result.single()
            if p0_record:
                data = dict(p0_record)
                data["incident_chains_persisted"] = True
                return data
            # ── Phase 1: Finding, chain, pivot IP, target host ──
            phase1_query = """
            MATCH (initiator:Host)-[:GENERATED]->(f:Finding {finding_id: $finding_id})
            OPTIONAL MATCH (f)-[:HAS_CHAIN]->(c:ChainNode)
            WITH initiator, f, c ORDER BY c.step_index
            WITH initiator, f, collect(CASE WHEN c IS NOT NULL THEN {
                entity_type: c.entity_type,
                entity_id: c.entity_id,
                entity_name: c.entity_name,
                pid: c.pid,
                timestamp: c.timestamp,
                step_index: c.step_index
            } END) AS source_chain_raw
            // Collect candidate pivot IPs from chain steps
            OPTIONAL MATCH (f)-[:HAS_CHAIN]->(step:ChainNode)
            WHERE step.entity_type = 'ip'
            WITH initiator, f, source_chain_raw,
                 collect(DISTINCT step.entity_id) AS chain_ips
            // Collect candidate pivot IPs from INVOLVES_IP
            OPTIONAL MATCH (f)-[:INVOLVES_IP]->(ip:IP)
            WITH initiator, f, source_chain_raw, chain_ips,
                 collect(DISTINCT ip.address) AS ioc_ips
            WITH initiator, f, source_chain_raw,
                 [x IN chain_ips + ioc_ips WHERE x IS NOT NULL] AS candidate_ips
            // Find target host whose ip_addresses contains a candidate
            UNWIND CASE WHEN size(candidate_ips) > 0 THEN candidate_ips ELSE [null] END AS cip
            OPTIONAL MATCH (tgt:Host)
            WHERE cip IS NOT NULL
              AND tgt.agent_id <> initiator.agent_id
              AND cip IN tgt.ip_addresses
            WITH initiator, f, source_chain_raw, candidate_ips,
                 collect(DISTINCT {ip: cip, agent_id: tgt.agent_id,
                         hostname: tgt.hostname,
                         ip_addresses: tgt.ip_addresses}) AS tgt_matches
            WITH initiator, f, source_chain_raw, candidate_ips,
                 [m IN tgt_matches WHERE m.agent_id IS NOT NULL] AS valid_matches
            WITH initiator, f, source_chain_raw, candidate_ips,
                 CASE WHEN size(valid_matches) > 0 THEN valid_matches[0] ELSE null END AS tgt_match
            RETURN initiator.agent_id AS src_agent_id,
                   initiator.hostname AS src_hostname,
                   initiator.ip_addresses AS src_ip_addresses,
                   f.finding_id AS finding_id,
                   f.title AS title,
                   f.severity AS severity,
                   f.timestamp AS timestamp,
                   f.description AS description,
                   [s IN source_chain_raw WHERE s IS NOT NULL] AS source_chain,
                   CASE WHEN tgt_match IS NOT NULL THEN tgt_match.ip ELSE null END AS pivot_ip,
                   CASE WHEN tgt_match IS NOT NULL THEN tgt_match.agent_id ELSE null END AS dst_agent_id,
                   CASE WHEN tgt_match IS NOT NULL THEN tgt_match.hostname ELSE null END AS dst_hostname
            LIMIT 1
            """
            result = session.run(phase1_query, {"finding_id": finding_id})
            record = result.single()
            if not record:
                return {}

            data = dict(record)
            dst_agent_id = data.get("dst_agent_id")
            src_ip_addresses = data.get("src_ip_addresses") or []
            target_chain: list[dict] = []

            # ── Phase 2A: Target chain — finding with IP match ──
            # Check both chain steps and IOC INVOLVES_IP edges.
            if dst_agent_id and src_ip_addresses:
                phase2a_query = """
                CALL {
                    MATCH (dst:Host {agent_id: $dst_agent_id})-[:GENERATED]->(tf:Finding)
                          -[:HAS_CHAIN]->(tc:ChainNode)
                    WHERE tc.entity_type = 'ip' AND tc.entity_id IN $src_ips
                    RETURN tf ORDER BY tf.timestamp DESC LIMIT 1
                    UNION
                    MATCH (dst:Host {agent_id: $dst_agent_id})-[:GENERATED]->(tf:Finding)
                          -[:INVOLVES_IP]->(ip:IP)
                    WHERE ip.address IN $src_ips
                    RETURN tf ORDER BY tf.timestamp DESC LIMIT 1
                }
                WITH tf ORDER BY tf.timestamp DESC LIMIT 1
                MATCH (tf)-[:HAS_CHAIN]->(tc2:ChainNode)
                WITH tc2 ORDER BY tc2.step_index
                RETURN collect({
                    entity_type: tc2.entity_type,
                    entity_id: tc2.entity_id,
                    entity_name: tc2.entity_name,
                    pid: tc2.pid,
                    timestamp: tc2.timestamp,
                    step_index: tc2.step_index
                }) AS target_chain
                """
                r2a = session.run(
                    phase2a_query,
                    {"dst_agent_id": dst_agent_id, "src_ips": src_ip_addresses},
                )
                rec2a = r2a.single()
                if rec2a and rec2a["target_chain"]:
                    target_chain = rec2a["target_chain"]

            # ── Phase 2B: Federated XDR query for target chain ──
            # Query the TARGET agent for INBOUND connections from the
            # source's IPs — that reveals the process chain on the target
            # (e.g. sshd→bash) that received the lateral movement.
            if not target_chain and dst_agent_id:
                xdr_chain = None

                if settings_db:
                    victim_qtype = "lateral_victim_trace"
                    victim_qkey = f"{finding_id}:victim"
                    xdr_result = settings_db.get_xdr_result(victim_qkey, victim_qtype)

                    if xdr_result is None:
                        import uuid
                        port = self._extract_finding_port(session, finding_id)
                        settings_db.enqueue_xdr_query(
                            str(uuid.uuid4()), dst_agent_id, victim_qkey,
                            victim_qtype,
                            json.dumps({"victim_ips": src_ip_addresses,
                                        "target_port": port,
                                        "finding_ts": data.get("timestamp") or 0}),
                        )
                        data["target_chain_pending"] = True

                    elif xdr_result["status"] == "pending":
                        data["target_chain_pending"] = True

                    elif xdr_result["status"] == "completed":
                        try:
                            result_data = json.loads(xdr_result["result_json"])
                            records = result_data.get("records", [])
                            if records:
                                xdr_chain = _build_chain_from_xdr_records(
                                    records, reverse=True,
                                )
                                data["target_chain_xdr_stitched"] = True
                        except (json.JSONDecodeError, KeyError):
                            pass

                if xdr_chain:
                    target_chain = xdr_chain
                elif "target_chain_pending" not in data:
                    # ── Phase 2B fallback: OCSF synthetic chain ──
                    ocsf_chain = None
                    incident_id = None
                    if settings_db:
                        incident_id = self._get_incident_id_for_finding(
                            session, finding_id,
                        )
                        if incident_id:
                            ocsf_rows = settings_db.get_ocsf_evidence(incident_id)
                            if ocsf_rows:
                                ocsf_chain = _build_chain_from_ocsf_evidence(
                                    ocsf_rows, dst_agent_id,
                                    src_ip_addresses,
                                )
                    if ocsf_chain:
                        target_chain = ocsf_chain
                        data["target_chain_ocsf_synthetic"] = True
                        # Persist so Phase 0 serves it instantly on next load
                        if incident_id:
                            self.persist_incident_chains(
                                incident_id, [], target_chain,
                            )
                    else:
                        # Final fallback: just the pivot IP
                        pivot_ip = data.get("pivot_ip") or ""
                        target_chain = []
                        if pivot_ip:
                            target_chain.append(
                                {"entity_type": "ip", "entity_id": pivot_ip,
                                 "entity_name": pivot_ip, "pid": 0,
                                 "timestamp": 0, "step_index": 0},
                            )
                        data["target_chain_inferred"] = True

            # ── Phase 2C: Federated XDR query for source chain ──
            # If Phase 1 returned no chain for the source (chain data
            # not ingested to Neo4j), query the SOURCE agent for OUTBOUND
            # connections to the target's pivot IP.
            source_chain = data.get("source_chain") or []
            src_agent_id = data.get("src_agent_id")
            pivot_ip = data.get("pivot_ip")

            if not source_chain and src_agent_id and pivot_ip and settings_db:
                xdr_source_chain = None
                source_qtype = "lateral_source_trace"
                source_qkey = f"{finding_id}:source"
                xdr_result = settings_db.get_xdr_result(source_qkey, source_qtype)

                if xdr_result is None:
                    import uuid
                    port = self._extract_finding_port(session, finding_id)
                    settings_db.enqueue_xdr_query(
                        str(uuid.uuid4()), src_agent_id, source_qkey,
                        source_qtype,
                        json.dumps({"dst_ips": [pivot_ip],
                                    "target_port": port,
                                    "finding_ts": data.get("timestamp") or 0}),
                    )
                    data["source_chain_pending"] = True

                elif xdr_result["status"] == "pending":
                    data["source_chain_pending"] = True

                elif xdr_result["status"] == "completed":
                    try:
                        result_data = json.loads(xdr_result["result_json"])
                        records = result_data.get("records", [])
                        if records:
                            xdr_source_chain = _build_chain_from_xdr_records(
                                records,
                            )
                            data["source_chain_xdr_stitched"] = True
                    except (json.JSONDecodeError, KeyError):
                        pass

                if xdr_source_chain:
                    source_chain = xdr_source_chain

            data["source_chain"] = source_chain
            data["target_chain"] = target_chain

            # Remove internal fields and build final response
            data.pop("src_ip_addresses", None)
            return data

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
               h.ioc_stats_json AS ioc_stats_json,
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
                        "ioc_stats_json": record["ioc_stats_json"],
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

    # ── Port extraction ──

    def _extract_finding_port(self, session, finding_id: str) -> int | None:
        """Extract the destination port from a finding's IOCs."""
        result = session.run(
            "MATCH (f:Finding {finding_id: $fid}) RETURN f.iocs AS iocs_json",
            {"fid": finding_id},
        )
        record = result.single()
        if not record or not record["iocs_json"]:
            return None
        try:
            iocs = json.loads(record["iocs_json"])
            ports = iocs.get("ports", [])
            return int(ports[0]) if ports else None
        except (json.JSONDecodeError, ValueError, IndexError, TypeError):
            return None

    def extract_finding_port(self, finding_id: str) -> int | None:
        """Extract the destination port from a finding's IOCs (standalone session)."""
        with self._driver.session() as session:
            return self._extract_finding_port(session, finding_id)

    def _get_incident_id_for_finding(self, session, finding_id: str) -> str | None:
        """Look up the incident_id that owns a given finding."""
        result = session.run(
            "MATCH (inc:Incident)-[:SOURCE_FINDING]->(f:Finding {finding_id: $fid}) "
            "RETURN inc.incident_id AS incident_id LIMIT 1",
            {"fid": finding_id},
        )
        record = result.single()
        return record["incident_id"] if record else None

    # ── Incident management ──

    def check_finding_for_lateral_movement(self, agent_id: str, finding_id: str) -> list[dict]:
        """Check if a single finding's IPs match any other host's ip_addresses.

        Returns list of {dst_agent_id, dst_hostname, pivot_ip} for each match.
        """
        query = """
        MATCH (initiator:Host {agent_id: $agent_id})-[:GENERATED]->(f:Finding {finding_id: $finding_id})
        OPTIONAL MATCH (f)-[:HAS_CHAIN]->(step:ChainNode)
        WHERE step.entity_type = 'ip'
        WITH initiator, f, collect(DISTINCT step.entity_id) AS chain_ips
        OPTIONAL MATCH (f)-[:INVOLVES_IP]->(ip:IP)
        WITH initiator, f, chain_ips, collect(DISTINCT ip.address) AS ioc_ips
        WITH initiator, f, [x IN chain_ips + ioc_ips WHERE x IS NOT NULL] AS candidate_ips
        WHERE size(candidate_ips) > 0
        UNWIND candidate_ips AS cip
        MATCH (target:Host)
        WHERE target.agent_id <> initiator.agent_id
          AND cip IN target.ip_addresses
        RETURN DISTINCT target.agent_id AS dst_agent_id,
               target.hostname AS dst_hostname,
               cip AS pivot_ip
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id, "finding_id": finding_id})
            return [dict(record) for record in result]

    def check_finding_for_follow_on(self, agent_id: str, finding_id: str) -> list[str]:
        """Link finding to active incidents where this agent is the target.

        Only links medium+ severity findings to avoid polluting incidents
        with noise (info/low findings).
        Creates FOLLOW_ON relationships and bumps updated_at.
        Returns list of incident_ids that were linked.
        """
        query = """
        MATCH (inc:Incident {dst_agent_id: $agent_id})
        WHERE inc.status = 'active'
        MATCH (f:Finding {finding_id: $finding_id})
        WHERE f.severity IN ['medium', 'high', 'critical']
        MERGE (inc)-[:FOLLOW_ON]->(f)
        SET inc.updated_at = $now
        RETURN inc.incident_id AS incident_id
        """
        with self._driver.session() as session:
            result = session.run(query, {
                "agent_id": agent_id,
                "finding_id": finding_id,
                "now": int(time.time()),
            })
            return [record["incident_id"] for record in result]

    def find_active_campaign(
        self,
        agent_ids: list[str],
        ips: list[str],
        window_hours: int = 12,
    ) -> str | None:
        """Find an active incident/campaign that overlaps with the given agents or IPs.

        Returns the incident_id if found, None otherwise.
        """
        cutoff = int(time.time()) - (window_hours * 3600)
        query = """
        MATCH (inc:Incident)
        WHERE inc.status IN ['detected', 'sweeping', 'active']
          AND inc.created_at > $cutoff
          AND (inc.src_agent_id IN $agent_ids
               OR inc.dst_agent_id IN $agent_ids
               OR inc.pivot_ip IN $ips)
        RETURN inc.incident_id AS incident_id
        ORDER BY inc.created_at DESC
        LIMIT 1
        """
        with self._driver.session() as session:
            result = session.run(query, {
                "cutoff": cutoff,
                "agent_ids": agent_ids,
                "ips": ips,
            })
            record = result.single()
            return record["incident_id"] if record else None

    def append_finding_to_incident(
        self,
        incident_id: str,
        finding_id: str,
        src_agent_id: str,
        dst_agent_id: str,
        pivot_ip: str,
    ) -> None:
        """Append a finding to an existing incident/campaign.

        Creates SOURCE_FINDING rel, INVOLVES_HOST for new hosts,
        PIVOT_VIA for new IPs, and bumps updated_at.
        """
        now = int(time.time())
        with self._driver.session() as session:
            # Link finding
            session.run(
                """
                MATCH (inc:Incident {incident_id: $incident_id})
                MATCH (f:Finding {finding_id: $finding_id})
                MERGE (inc)-[:SOURCE_FINDING]->(f)
                SET inc.updated_at = $now
                """,
                {"incident_id": incident_id, "finding_id": finding_id, "now": now},
            )
            # INVOLVES_HOST for src
            session.run(
                """
                MATCH (inc:Incident {incident_id: $incident_id})
                OPTIONAL MATCH (h:Host {agent_id: $agent_id})
                FOREACH (_ IN CASE WHEN h IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (inc)-[:INVOLVES_HOST]->(h)
                )
                """,
                {"incident_id": incident_id, "agent_id": src_agent_id},
            )
            # INVOLVES_HOST for dst (if different)
            if dst_agent_id and dst_agent_id != src_agent_id:
                session.run(
                    """
                    MATCH (inc:Incident {incident_id: $incident_id})
                    OPTIONAL MATCH (h:Host {agent_id: $agent_id})
                    FOREACH (_ IN CASE WHEN h IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (inc)-[:INVOLVES_HOST]->(h)
                    )
                    """,
                    {"incident_id": incident_id, "agent_id": dst_agent_id},
                )
            # PIVOT_VIA for new IP (skip if empty — vertical movement)
            if pivot_ip:
                session.run(
                    """
                    MATCH (inc:Incident {incident_id: $incident_id})
                    MERGE (ip:IP {address: $pivot_ip})
                    MERGE (inc)-[:PIVOT_VIA]->(ip)
                    """,
                    {"incident_id": incident_id, "pivot_ip": pivot_ip},
                )
            # Upgrade to campaign if incident now has both lateral and vertical findings
            session.run(
                """
                MATCH (inc:Incident {incident_id: $incident_id})
                WHERE inc.incident_type <> 'campaign'
                WITH inc
                OPTIONAL MATCH (inc)-[:SOURCE_FINDING]->(f:Finding)-[:INVOLVES_IP]->(ip:IP)
                MATCH (inc)-[:INVOLVES_HOST]->(h:Host)
                WITH inc, count(DISTINCT h) AS host_count
                WHERE host_count > 2
                SET inc.incident_type = 'campaign'
                """,
                {"incident_id": incident_id},
            )
        logger.info("Appended finding %s to incident %s", finding_id, incident_id)

    def check_finding_for_vertical_movement(self, agent_id: str, finding_id: str) -> list[dict]:
        """Check if a finding contains privilege escalation (user context change).

        Returns list of {agent_id, hostname, original_user, escalated_user}.
        """
        query = """
        MATCH (h:Host {agent_id: $agent_id})-[:GENERATED]->(f:Finding {finding_id: $finding_id})
              -[:HAS_CHAIN]->(c1:ChainNode)
        WHERE c1.entity_type = 'user'
        MATCH (f)-[:HAS_CHAIN]->(c2:ChainNode)
        WHERE c2.entity_type = 'user'
          AND c2.step_index > c1.step_index
          AND c2.entity_id <> c1.entity_id
          AND (c2.entity_name = 'root' OR c2.entity_id = '0')
        RETURN h.agent_id AS agent_id,
               h.hostname AS hostname,
               c1.entity_name AS original_user,
               c2.entity_name AS escalated_user
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id, "finding_id": finding_id})
            return [dict(record) for record in result]

    def store_incident_diamond_assessment(self, incident_id: str, assessment: dict) -> None:
        """Store Diamond assessment JSON on the Incident node."""
        now = int(time.time())
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})
        SET inc.diamond_assessment_json = $assessment_json,
            inc.diamond_assessed_at = $now
        """
        with self._driver.session() as session:
            session.run(query, {
                "incident_id": incident_id,
                "assessment_json": json.dumps(assessment),
                "now": now,
            })

    def get_incident_involved_agents(self, incident_id: str) -> list[str]:
        """Get agent IDs for all hosts involved in an incident."""
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})-[:INVOLVES_HOST]->(h:Host)
        RETURN h.agent_id AS agent_id
        """
        with self._driver.session() as session:
            result = session.run(query, {"incident_id": incident_id})
            return [record["agent_id"] for record in result]

    def has_incident_for_finding(self, finding_id: str, pivot_ip: str) -> bool:
        """Check if an incident already exists for this finding+pivot_ip combo."""
        query = """
        MATCH (inc:Incident)-[:SOURCE_FINDING]->(f:Finding {finding_id: $finding_id})
        WHERE inc.pivot_ip = $pivot_ip
        RETURN count(inc) AS cnt
        """
        with self._driver.session() as session:
            result = session.run(query, {"finding_id": finding_id, "pivot_ip": pivot_ip})
            record = result.single()
            return record["cnt"] > 0 if record else False

    def create_incident(
        self,
        incident_id: str,
        finding_id: str,
        src_agent_id: str,
        dst_agent_id: str,
        pivot_ip: str,
        dst_port: int | None = None,
    ) -> None:
        """Create an Incident node with relationships to source finding and hosts."""
        now = int(time.time())
        query = """
        MERGE (inc:Incident {incident_id: $incident_id})
        SET inc.incident_type = 'lateral_movement',
            inc.status = 'detected',
            inc.src_agent_id = $src_agent_id,
            inc.dst_agent_id = $dst_agent_id,
            inc.pivot_ip = $pivot_ip,
            inc.dst_port = $dst_port,
            inc.created_at = $now,
            inc.updated_at = $now
        WITH inc
        MATCH (f:Finding {finding_id: $finding_id})
        MERGE (inc)-[:SOURCE_FINDING]->(f)
        WITH inc
        OPTIONAL MATCH (src:Host {agent_id: $src_agent_id})
        FOREACH (_ IN CASE WHEN src IS NOT NULL THEN [1] ELSE [] END |
            MERGE (inc)-[:INVOLVES_HOST]->(src)
        )
        WITH inc
        OPTIONAL MATCH (dst:Host {agent_id: $dst_agent_id})
        FOREACH (_ IN CASE WHEN dst IS NOT NULL THEN [1] ELSE [] END |
            MERGE (inc)-[:INVOLVES_HOST]->(dst)
        )
        WITH inc
        MERGE (ip:IP {address: $pivot_ip})
        MERGE (inc)-[:PIVOT_VIA]->(ip)
        """
        with self._driver.session() as session:
            session.run(query, {
                "incident_id": incident_id,
                "finding_id": finding_id,
                "src_agent_id": src_agent_id,
                "dst_agent_id": dst_agent_id,
                "pivot_ip": pivot_ip,
                "dst_port": dst_port,
                "now": now,
            })
        logger.info(
            "Created incident %s: %s → %s via %s:%s",
            incident_id, src_agent_id, dst_agent_id, pivot_ip, dst_port,
        )

    def get_incidents_by_status(self, status: str) -> list[dict]:
        """Get all incidents with a given status."""
        query = """
        MATCH (inc:Incident {status: $status})
        OPTIONAL MATCH (inc)-[:SOURCE_FINDING]->(f:Finding)
        RETURN inc.incident_id AS incident_id,
               inc.incident_type AS incident_type,
               inc.status AS status,
               inc.src_agent_id AS src_agent_id,
               inc.dst_agent_id AS dst_agent_id,
               inc.pivot_ip AS pivot_ip,
               inc.dst_port AS dst_port,
               inc.created_at AS created_at,
               inc.updated_at AS updated_at,
               f.finding_id AS finding_id
        ORDER BY inc.created_at ASC
        """
        with self._driver.session() as session:
            result = session.run(query, {"status": status})
            return [dict(record) for record in result]

    def update_incident_status(self, incident_id: str, new_status: str) -> None:
        """Transition an incident to a new status."""
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})
        SET inc.status = $new_status,
            inc.updated_at = $now
        """
        with self._driver.session() as session:
            session.run(query, {
                "incident_id": incident_id,
                "new_status": new_status,
                "now": int(time.time()),
            })

    def get_incident_src_ips(self, incident_id: str) -> list[str]:
        """Get the source host's ip_addresses for XDR query params."""
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})
        MATCH (src:Host {agent_id: inc.src_agent_id})
        RETURN src.ip_addresses AS ip_addresses
        """
        with self._driver.session() as session:
            result = session.run(query, {"incident_id": incident_id})
            record = result.single()
            return record["ip_addresses"] if record and record["ip_addresses"] else []

    def persist_incident_chains(
        self,
        incident_id: str,
        source_chain: list[dict],
        target_chain: list[dict],
    ) -> None:
        """Write ChainNodes linked to an Incident via HAS_SOURCE_CHAIN / HAS_TARGET_CHAIN."""
        with self._driver.session() as session:
            for rel_type, chain in [("HAS_SOURCE_CHAIN", source_chain), ("HAS_TARGET_CHAIN", target_chain)]:
                for step in chain:
                    node_id = f"{incident_id}:{rel_type.lower()}:{step.get('step_index', 0)}"
                    session.run(
                        """
                        MERGE (c:ChainNode {chain_node_id: $chain_node_id})
                        SET c.finding_id = $incident_id,
                            c.step_index = $step_index,
                            c.entity_type = $entity_type,
                            c.entity_id = $entity_id,
                            c.entity_name = $entity_name,
                            c.pid = $pid,
                            c.timestamp = $timestamp,
                            c.host_agent_id = $host_agent_id
                        WITH c
                        MATCH (inc:Incident {incident_id: $incident_id})
                        MERGE (inc)-[r:""" + rel_type + """ {step_index: $step_index}]->(c)
                        """,
                        {
                            "chain_node_id": node_id,
                            "incident_id": incident_id,
                            "step_index": step.get("step_index", 0),
                            "entity_type": step.get("entity_type", ""),
                            "entity_id": step.get("entity_id", ""),
                            "entity_name": step.get("entity_name", ""),
                            "pid": step.get("pid", 0),
                            "timestamp": step.get("timestamp", 0),
                            "host_agent_id": step.get("host_agent_id", ""),
                        },
                    )

    def list_incidents(self, status: str | None = None, limit: int = 50) -> list[dict]:
        """List incidents for dashboard API."""
        if status:
            query = """
            MATCH (inc:Incident {status: $status})
            OPTIONAL MATCH (inc)-[:FOLLOW_ON]->(fo:Finding)
            WITH inc, count(fo) AS follow_on_count
            OPTIONAL MATCH (src:Host {agent_id: inc.src_agent_id})
            OPTIONAL MATCH (dst:Host {agent_id: inc.dst_agent_id})
            RETURN inc.incident_id AS incident_id,
                   inc.incident_type AS incident_type,
                   inc.status AS status,
                   inc.src_agent_id AS src_agent_id,
                   src.hostname AS src_hostname,
                   inc.dst_agent_id AS dst_agent_id,
                   dst.hostname AS dst_hostname,
                   inc.pivot_ip AS pivot_ip,
                   inc.created_at AS created_at,
                   inc.updated_at AS updated_at,
                   follow_on_count
            ORDER BY inc.updated_at DESC
            LIMIT $limit
            """
            params = {"status": status, "limit": limit}
        else:
            query = """
            MATCH (inc:Incident)
            OPTIONAL MATCH (inc)-[:FOLLOW_ON]->(fo:Finding)
            WITH inc, count(fo) AS follow_on_count
            OPTIONAL MATCH (src:Host {agent_id: inc.src_agent_id})
            OPTIONAL MATCH (dst:Host {agent_id: inc.dst_agent_id})
            RETURN inc.incident_id AS incident_id,
                   inc.incident_type AS incident_type,
                   inc.status AS status,
                   inc.src_agent_id AS src_agent_id,
                   src.hostname AS src_hostname,
                   inc.dst_agent_id AS dst_agent_id,
                   dst.hostname AS dst_hostname,
                   inc.pivot_ip AS pivot_ip,
                   inc.created_at AS created_at,
                   inc.updated_at AS updated_at,
                   follow_on_count
            ORDER BY inc.updated_at DESC
            LIMIT $limit
            """
            params = {"limit": limit}
        with self._driver.session() as session:
            result = session.run(query, params)
            return [dict(record) for record in result]

    def get_incident_detail(self, incident_id: str) -> dict | None:
        """Full incident detail with chains, findings, involved hosts, and Diamond assessment."""
        with self._driver.session() as session:
            # Base info
            base_query = """
            MATCH (inc:Incident {incident_id: $incident_id})
            OPTIONAL MATCH (src:Host {agent_id: inc.src_agent_id})
            OPTIONAL MATCH (dst:Host {agent_id: inc.dst_agent_id})
            RETURN inc.incident_id AS incident_id,
                   inc.incident_type AS incident_type,
                   inc.status AS status,
                   inc.src_agent_id AS src_agent_id,
                   src.hostname AS src_hostname,
                   inc.dst_agent_id AS dst_agent_id,
                   dst.hostname AS dst_hostname,
                   inc.pivot_ip AS pivot_ip,
                   inc.created_at AS created_at,
                   inc.updated_at AS updated_at,
                   inc.diamond_assessment_json AS diamond_assessment_json,
                   inc.diamond_assessed_at AS diamond_assessed_at
            """
            result = session.run(base_query, {"incident_id": incident_id})
            record = result.single()
            if not record:
                return None
            data = dict(record)

            # All source findings (campaign may have multiple)
            sf_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:SOURCE_FINDING]->(sf:Finding)
            OPTIONAL MATCH (h:Host)-[:GENERATED]->(sf)
            RETURN sf.finding_id AS finding_id, sf.title AS title,
                   sf.severity AS severity, sf.timestamp AS timestamp,
                   h.hostname AS hostname, h.agent_id AS agent_id
            ORDER BY sf.timestamp ASC
            """
            sf_result = session.run(sf_query, {"incident_id": incident_id})
            source_findings = [dict(r) for r in sf_result]
            data["source_findings"] = source_findings
            # Back-compat: expose first finding as source_finding_*
            if source_findings:
                data["source_finding_id"] = source_findings[0]["finding_id"]
                data["source_finding_title"] = source_findings[0]["title"]
                data["source_finding_severity"] = source_findings[0]["severity"]
            else:
                data["source_finding_id"] = None
                data["source_finding_title"] = None
                data["source_finding_severity"] = None

            # All involved hosts
            ih_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:INVOLVES_HOST]->(h:Host)
            RETURN h.agent_id AS agent_id, h.hostname AS hostname,
                   h.ip_addresses AS ip_addresses
            """
            ih_result = session.run(ih_query, {"incident_id": incident_id})
            data["involved_hosts"] = [dict(r) for r in ih_result]

            # Source chain
            sc_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:HAS_SOURCE_CHAIN]->(c:ChainNode)
            RETURN c.entity_type AS entity_type, c.entity_id AS entity_id,
                   c.entity_name AS entity_name, c.pid AS pid,
                   c.timestamp AS timestamp, c.step_index AS step_index
            ORDER BY c.step_index
            """
            sc_result = session.run(sc_query, {"incident_id": incident_id})
            data["source_chain"] = [dict(r) for r in sc_result]

            # Target chain
            tc_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:HAS_TARGET_CHAIN]->(c:ChainNode)
            RETURN c.entity_type AS entity_type, c.entity_id AS entity_id,
                   c.entity_name AS entity_name, c.pid AS pid,
                   c.timestamp AS timestamp, c.step_index AS step_index
            ORDER BY c.step_index
            """
            tc_result = session.run(tc_query, {"incident_id": incident_id})
            data["target_chain"] = [dict(r) for r in tc_result]

            # Per-finding chains (from Finding -[:HAS_CHAIN]-> ChainNode)
            fc_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:SOURCE_FINDING]->(sf:Finding)
            OPTIONAL MATCH (sf)-[:HAS_CHAIN]->(c:ChainNode)
            OPTIONAL MATCH (h:Host)-[:GENERATED]->(sf)
            RETURN sf.finding_id AS finding_id, sf.title AS title,
                   h.hostname AS hostname,
                   c.entity_type AS entity_type, c.entity_id AS entity_id,
                   c.entity_name AS entity_name, c.pid AS pid,
                   c.timestamp AS timestamp, c.step_index AS step_index
            ORDER BY sf.timestamp ASC, c.step_index ASC
            """
            fc_result = session.run(fc_query, {"incident_id": incident_id})
            finding_chains: dict[str, dict] = {}
            for r in fc_result:
                fid = r["finding_id"]
                if fid not in finding_chains:
                    finding_chains[fid] = {
                        "finding_id": fid,
                        "title": r["title"],
                        "hostname": r["hostname"],
                        "chain": [],
                    }
                if r["entity_type"]:
                    finding_chains[fid]["chain"].append({
                        "entity_type": r["entity_type"],
                        "entity_id": r["entity_id"],
                        "entity_name": r["entity_name"],
                        "pid": r["pid"],
                        "timestamp": r["timestamp"],
                        "step_index": r["step_index"],
                    })
            data["finding_chains"] = list(finding_chains.values())

            # Follow-on findings
            fo_query = """
            MATCH (inc:Incident {incident_id: $incident_id})-[:FOLLOW_ON]->(f:Finding)
            RETURN f.finding_id AS finding_id, f.title AS title,
                   f.severity AS severity, f.timestamp AS timestamp
            ORDER BY f.timestamp DESC
            LIMIT 100
            """
            fo_result = session.run(fo_query, {"incident_id": incident_id})
            data["follow_on_findings"] = [dict(r) for r in fo_result]

            return data

    def get_surveillance_targets(self, agent_id: str) -> dict:
        """Aggregate pivot IPs and compromised usernames from active incidents for an agent.

        Returns {"ips": [...], "users": [...]} or empty dict if no active incidents.
        """
        query = """
        MATCH (inc:Incident)
        WHERE inc.status = 'active'
          AND (inc.src_agent_id = $agent_id OR inc.dst_agent_id = $agent_id)
        OPTIONAL MATCH (inc)-[:HAS_SOURCE_CHAIN]->(sc:ChainNode)
        WHERE sc.entity_type = 'user'
        OPTIONAL MATCH (inc)-[:HAS_TARGET_CHAIN]->(tc:ChainNode)
        WHERE tc.entity_type = 'user'
        WITH collect(DISTINCT inc.pivot_ip) AS ips,
             collect(DISTINCT sc.entity_name) + collect(DISTINCT tc.entity_name) AS raw_users
        WITH ips, [u IN raw_users WHERE u IS NOT NULL] AS users
        RETURN ips, users
        """
        with self._driver.session() as session:
            result = session.run(query, {"agent_id": agent_id})
            record = result.single()
            if not record:
                return {}
            ips = record["ips"] or []
            users = list(set(record["users"] or []))
            if not ips and not users:
                return {}
            return {"ips": ips, "users": users}

    def get_incident_chain_usernames(self, incident_id: str) -> tuple[list[str], list[str]]:
        """Get usernames from persisted source/target chains for an incident.

        Returns (src_usernames, dst_usernames).
        """
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (inc)-[:HAS_SOURCE_CHAIN]->(sc:ChainNode)
        WHERE sc.entity_type = 'user' AND sc.entity_name IS NOT NULL
        WITH inc, collect(DISTINCT sc.entity_name) AS src_users
        OPTIONAL MATCH (inc)-[:HAS_TARGET_CHAIN]->(tc:ChainNode)
        WHERE tc.entity_type = 'user' AND tc.entity_name IS NOT NULL
        RETURN src_users, collect(DISTINCT tc.entity_name) AS dst_users
        """
        with self._driver.session() as session:
            result = session.run(query, {"incident_id": incident_id})
            record = result.single()
            if not record:
                return [], []
            return list(record["src_users"] or []), list(record["dst_users"] or [])

    def get_incident_chain_pids(self, incident_id: str) -> tuple[list[int], list[int]]:
        """Get process PIDs from persisted source/target chains for an incident.

        Lightweight alternative to get_incident_detail() — skips base info,
        follow-ons, and full chain traversal.

        Returns (src_pids, dst_pids).
        """
        query = """
        MATCH (inc:Incident {incident_id: $incident_id})
        OPTIONAL MATCH (inc)-[:HAS_SOURCE_CHAIN]->(sc:ChainNode)
        WHERE sc.entity_type = 'process' AND sc.pid > 0
        WITH inc, collect(DISTINCT sc.pid) AS src_pids
        OPTIONAL MATCH (inc)-[:HAS_TARGET_CHAIN]->(tc:ChainNode)
        WHERE tc.entity_type = 'process' AND tc.pid > 0
        RETURN src_pids, collect(DISTINCT tc.pid) AS dst_pids
        """
        with self._driver.session() as session:
            result = session.run(query, {"incident_id": incident_id})
            record = result.single()
            if not record:
                return [], []
            return list(record["src_pids"] or []), list(record["dst_pids"] or [])

    # ── Migration helpers ──

    def get_all_dashboard_users(self) -> list[dict]:
        """Get all dashboard users for migration to SQLite."""
        query = """
        MATCH (u:DashboardUser)
        RETURN u.username AS username,
               u.password_hash AS password_hash,
               u.role AS role,
               u.created_at AS created_at
        """
        with self._driver.session() as session:
            result = session.run(query)
            return [dict(record) for record in result]

    def get_all_registration_keys(self) -> list[dict]:
        """Get all registration keys for migration to SQLite."""
        query = """
        MATCH (k:RegistrationKey)
        RETURN k.key AS key, k.label AS label, k.created_at AS created_at,
               k.created_by AS created_by, k.expires_at AS expires_at,
               k.max_uses AS max_uses, k.use_count AS use_count,
               k.revoked AS revoked, k.revoked_at AS revoked_at,
               k.revoked_by AS revoked_by
        """
        with self._driver.session() as session:
            result = session.run(query)
            return [dict(record) for record in result]

    def close(self) -> None:
        """Close the Neo4j driver."""
        self._driver.close()
