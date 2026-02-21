"""Fleet management dashboard REST API.

Provides endpoints for viewing connected agents, recent findings,
cross-host correlation, lateral/vertical movement detection, and
SOC dashboard authentication.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel

from server.auth import get_current_user
from server.neo4j_client import Neo4jClient

app = FastAPI(title="EDR Fleet Dashboard", version="1.0.0")

# Set by app.py at startup
_neo4j: Neo4jClient | None = None
_settings = None


def set_neo4j(client: Neo4jClient) -> None:
    global _neo4j
    _neo4j = client


def set_settings(settings) -> None:
    global _settings
    _settings = settings


# ── Auth models ──


class LoginRequest(BaseModel):
    username: str
    password: str


# ── Auth endpoints (no JWT required) ──


@app.post("/api/auth/login")
async def login(body: LoginRequest):
    """Authenticate and return a JWT."""
    from server.auth import create_token, verify_password

    user = _neo4j.verify_dashboard_user(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(
        username=user["username"],
        role=user["role"],
        secret=_settings.jwt_secret,
        ttl_hours=_settings.jwt_ttl_hours,
    )
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    """Return current user info from JWT."""
    return {"username": user["sub"], "role": user["role"]}


# ── Fleet endpoints (JWT required) ──


@app.get("/api/fleet/agents")
async def list_agents(user: dict = Depends(get_current_user)):
    """List all registered agents with status and finding counts."""
    return _neo4j.get_fleet_status()


@app.get("/api/fleet/agents/{agent_id}")
async def agent_detail(agent_id: str, user: dict = Depends(get_current_user)):
    """Get detailed info for a specific agent."""
    detail = _neo4j.get_agent_detail(agent_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Agent not found")
    return detail


@app.get("/api/fleet/agents/{agent_id}/findings")
async def agent_findings(
    agent_id: str,
    limit: int = Query(default=100, le=500),
    user: dict = Depends(get_current_user),
):
    """Get findings for a specific agent."""
    return _neo4j.get_agent_findings(agent_id, limit=limit)


@app.get("/api/fleet/agents/{agent_id}/chains")
async def agent_chains(
    agent_id: str,
    limit: int = Query(default=200, le=1000),
    user: dict = Depends(get_current_user),
):
    """Get chain steps for a specific agent."""
    return _neo4j.get_agent_chain_steps(agent_id, limit=limit)


# ── Findings endpoints (JWT required) ──


@app.get("/api/fleet/findings")
async def fleet_findings(
    limit: int = Query(default=50, le=500),
    user: dict = Depends(get_current_user),
):
    """Recent findings across all agents."""
    return _neo4j.get_recent_findings(limit=limit)


@app.get("/api/fleet/findings/{finding_id}")
async def finding_detail(finding_id: str, user: dict = Depends(get_current_user)):
    """Get a finding with full chain data."""
    detail = _neo4j.get_finding_detail(finding_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Finding not found")
    return detail


# ── Movement detection endpoints (JWT required) ──


@app.get("/api/fleet/lateral-movements")
async def lateral_movements(
    limit: int = Query(default=50, le=200),
    user: dict = Depends(get_current_user),
):
    """Detected cross-GUID chain pairs (lateral movement)."""
    time_window = _settings.lateral_movement_time_window if _settings else 300
    return _neo4j.detect_lateral_movements(time_window=time_window, limit=limit)


@app.get("/api/fleet/lateral-movements/{src_finding}/{dst_finding}")
async def lateral_movement_detail(
    src_finding: str,
    dst_finding: str,
    user: dict = Depends(get_current_user),
):
    """Full stitched chain detail for a lateral movement pair."""
    detail = _neo4j.get_lateral_movement_detail(src_finding, dst_finding)
    if not detail:
        raise HTTPException(status_code=404, detail="Movement pair not found")
    return detail


@app.get("/api/fleet/vertical-movements")
async def vertical_movements(
    limit: int = Query(default=50, le=200),
    user: dict = Depends(get_current_user),
):
    """Privilege escalation chains within single agents."""
    return _neo4j.detect_vertical_movements(limit=limit)


@app.get("/api/fleet/host-connections")
async def host_connections(
    limit: int = Query(default=100, le=500),
    user: dict = Depends(get_current_user),
):
    """Host-to-host network connections map."""
    return _neo4j.get_host_to_host_connections(limit=limit)


# ── Existing endpoints (kept for compatibility) ──


@app.get("/api/fleet/cross-host/{ip}")
async def cross_host_connections(ip: str, user: dict = Depends(get_current_user)):
    """Show all agents with processes connecting to a given IP."""
    return _neo4j.get_cross_host_connections(ip)


# ── Registration key endpoints (JWT required) ──


class CreateKeyRequest(BaseModel):
    label: str
    expires_in: int | None = None  # seconds from now, or None for no expiry
    max_uses: int | None = None


@app.get("/api/fleet/registration-keys")
async def list_registration_keys(user: dict = Depends(get_current_user)):
    """List all registration keys."""
    return _neo4j.list_registration_keys()


@app.post("/api/fleet/registration-keys")
async def create_registration_key(body: CreateKeyRequest, user: dict = Depends(get_current_user)):
    """Generate a new registration key."""
    import time

    key = secrets.token_hex(32)  # 64-char hex string
    expires_at = None
    if body.expires_in is not None and body.expires_in > 0:
        expires_at = int(time.time()) + body.expires_in

    result = _neo4j.create_registration_key(
        key=key,
        label=body.label,
        created_by=user["sub"],
        expires_at=expires_at,
        max_uses=body.max_uses,
    )
    return result


@app.post("/api/fleet/registration-keys/{key}/revoke")
async def revoke_registration_key(key: str, user: dict = Depends(get_current_user)):
    """Revoke a registration key."""
    ok = _neo4j.revoke_registration_key(key, revoked_by=user["sub"])
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "revoked"}


@app.delete("/api/fleet/registration-keys/{key}")
async def delete_registration_key(key: str, user: dict = Depends(get_current_user)):
    """Permanently delete a registration key."""
    ok = _neo4j.delete_registration_key(key)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "deleted"}


# ── Health check (no auth) ──


@app.get("/health")
async def health():
    return {"status": "ok"}
