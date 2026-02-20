"""Fleet management dashboard REST API.

Provides endpoints for viewing connected agents, recent findings,
and cross-host correlation data from the Neo4j graph.
"""

from __future__ import annotations

from fastapi import FastAPI, Query

from server.neo4j_client import Neo4jClient

app = FastAPI(title="EDR Fleet Dashboard", version="0.1.0")

# Set by app.py at startup
_neo4j: Neo4jClient | None = None


def set_neo4j(client: Neo4jClient) -> None:
    global _neo4j
    _neo4j = client


@app.get("/api/fleet/agents")
async def list_agents():
    """List all registered agents with status and finding counts."""
    return _neo4j.get_fleet_status()


@app.get("/api/fleet/findings")
async def fleet_findings(limit: int = Query(default=50, le=500)):
    """Recent findings across all agents."""
    return _neo4j.get_recent_findings(limit=limit)


@app.get("/api/fleet/cross-host/{ip}")
async def cross_host_connections(ip: str):
    """Show all agents with processes connecting to a given IP.

    This is the primary lateral movement detection endpoint.
    If multiple hosts are connecting to the same suspicious IP,
    it may indicate command-and-control or lateral movement.
    """
    return _neo4j.get_cross_host_connections(ip)


@app.get("/health")
async def health():
    return {"status": "ok"}
