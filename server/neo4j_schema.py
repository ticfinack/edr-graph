"""Neo4j Cypher schema for cross-host graph correlation.

The central Neo4j graph mirrors the per-host Kuzu schema but adds:
- Host nodes for agent identity
- host_id properties on all nodes for cross-host correlation
- Lateral movement detection via cross-host IP connections
- ChainNode graph for attack chain stitching across agents
- DashboardUser for SOC authentication
"""

CONSTRAINTS = [
    "CREATE CONSTRAINT host_agent_id IF NOT EXISTS FOR (h:Host) REQUIRE h.agent_id IS UNIQUE",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE",
    "CREATE CONSTRAINT chain_node_id IF NOT EXISTS FOR (c:ChainNode) REQUIRE c.chain_node_id IS UNIQUE",
    "CREATE CONSTRAINT dashboard_user_username IF NOT EXISTS FOR (u:DashboardUser) REQUIRE u.username IS UNIQUE",
    "CREATE CONSTRAINT registration_key_unique IF NOT EXISTS FOR (k:RegistrationKey) REQUIRE k.key IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX process_host IF NOT EXISTS FOR (p:Process) ON (p.host_id)",
    "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
    "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
    "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX finding_timestamp IF NOT EXISTS FOR (f:Finding) ON (f.timestamp)",
    "CREATE INDEX chain_node_host IF NOT EXISTS FOR (c:ChainNode) ON (c.host_agent_id)",
    "CREATE INDEX chain_node_entity IF NOT EXISTS FOR (c:ChainNode) ON (c.entity_type, c.entity_id)",
    "CREATE INDEX registration_key_revoked IF NOT EXISTS FOR (k:RegistrationKey) ON (k.revoked)",
]

INIT_QUERIES = CONSTRAINTS + INDEXES
