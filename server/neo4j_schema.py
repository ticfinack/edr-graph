"""Neo4j Cypher schema for cross-host graph correlation.

The central Neo4j graph mirrors the per-host Kuzu schema but adds:
- Host nodes for agent identity
- host_id properties on all nodes for cross-host correlation
- Lateral movement detection via cross-host IP connections
"""

CONSTRAINTS = [
    "CREATE CONSTRAINT host_agent_id IF NOT EXISTS FOR (h:Host) REQUIRE h.agent_id IS UNIQUE",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX process_host IF NOT EXISTS FOR (p:Process) ON (p.host_id)",
    "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
    "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
    "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX finding_timestamp IF NOT EXISTS FOR (f:Finding) ON (f.timestamp)",
]

INIT_QUERIES = CONSTRAINTS + INDEXES
