"""Fleet management dashboard REST API.

Provides endpoints for viewing connected agents, recent findings,
cross-host correlation, lateral/vertical movement detection,
SOC dashboard authentication, user management, and settings.
"""

from __future__ import annotations

import secrets
import time

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel

from server.auth import get_current_user
from server.neo4j_client import Neo4jClient
from server.settings_db import SettingsDB

app = FastAPI(title="EDR Fleet Dashboard", version="1.0.0")

# Set by app.py at startup
_neo4j: Neo4jClient | None = None
_settings = None
_settings_db: SettingsDB | None = None


def set_neo4j(client: Neo4jClient) -> None:
    global _neo4j
    _neo4j = client


def set_settings(settings) -> None:
    global _settings
    _settings = settings


def set_settings_db(db: SettingsDB) -> None:
    global _settings_db
    _settings_db = db


# ── Auth models ──


class LoginRequest(BaseModel):
    username: str
    password: str


# ── Auth endpoints (no JWT required) ──


@app.post("/api/auth/login")
def login(body: LoginRequest):
    """Authenticate and return a JWT."""
    from server.auth import create_token, verify_password

    user = _settings_db.get_user(body.username)
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
def list_agents(user: dict = Depends(get_current_user)):
    """List all registered agents with status, finding counts, and tags."""
    agents = _neo4j.get_fleet_status()
    agent_ids = [a["agent_id"] for a in agents if "agent_id" in a]
    if agent_ids and _settings_db:
        bulk_tags = _settings_db.get_bulk_agent_tags(agent_ids)
        for a in agents:
            a["tags"] = bulk_tags.get(a.get("agent_id", ""), [])
    return agents


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
    return _neo4j.detect_lateral_movements(limit=limit)


@app.get("/api/fleet/lateral-movements/{finding_id}")
async def lateral_movement_detail(
    finding_id: str,
    user: dict = Depends(get_current_user),
):
    """Chain detail for a lateral movement finding, with source host info."""
    detail = _neo4j.get_lateral_movement_detail(finding_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Movement not found")
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


# ── Registration key endpoints (JWT required, backed by SQLite) ──


class CreateKeyRequest(BaseModel):
    label: str
    expires_in: int | None = None  # seconds from now, or None for no expiry
    max_uses: int | None = None


@app.get("/api/fleet/registration-keys")
def list_registration_keys(user: dict = Depends(get_current_user)):
    """List all registration keys."""
    return _settings_db.list_registration_keys()


@app.post("/api/fleet/registration-keys")
def create_registration_key(body: CreateKeyRequest, user: dict = Depends(get_current_user)):
    """Generate a new registration key."""
    key = secrets.token_hex(32)
    expires_at = None
    if body.expires_in is not None and body.expires_in > 0:
        expires_at = int(time.time()) + body.expires_in

    result = _settings_db.create_registration_key(
        key=key,
        label=body.label,
        created_by=user["sub"],
        expires_at=expires_at,
        max_uses=body.max_uses,
    )
    return result


@app.post("/api/fleet/registration-keys/{key}/revoke")
def revoke_registration_key(key: str, user: dict = Depends(get_current_user)):
    """Revoke a registration key."""
    ok = _settings_db.revoke_registration_key(key, revoked_by=user["sub"])
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "revoked"}


@app.delete("/api/fleet/registration-keys/{key}")
def delete_registration_key(key: str, user: dict = Depends(get_current_user)):
    """Permanently delete a registration key."""
    ok = _settings_db.delete_registration_key(key)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "deleted"}


# ── User management endpoints (JWT required) ──


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "admin"


class UpdateUserRequest(BaseModel):
    password: str | None = None
    role: str | None = None


@app.get("/api/settings/users")
def list_users(user: dict = Depends(get_current_user)):
    """List all users (no password_hash)."""
    return _settings_db.list_users()


@app.post("/api/settings/users")
def create_user(body: CreateUserRequest, user: dict = Depends(get_current_user)):
    """Create a new user."""
    from server.auth import hash_password

    if _settings_db.get_user(body.username):
        raise HTTPException(status_code=409, detail="User already exists")
    return _settings_db.create_user(body.username, hash_password(body.password), role=body.role)


@app.put("/api/settings/users/{username}")
def update_user(username: str, body: UpdateUserRequest, user: dict = Depends(get_current_user)):
    """Update a user's password and/or role."""
    from server.auth import hash_password

    pw_hash = hash_password(body.password) if body.password else None
    ok = _settings_db.update_user(username, password_hash=pw_hash, role=body.role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "updated"}


@app.delete("/api/settings/users/{username}")
def delete_user(username: str, user: dict = Depends(get_current_user)):
    """Delete a user. Prevent self-deletion."""
    if user["sub"] == username:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    ok = _settings_db.delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "deleted"}


# ── Server settings endpoints (JWT required) ──

_EDITABLE_SERVER_SETTINGS = {"jwt_ttl_hours", "lateral_movement_time_window", "ntp_server", "ntp_sync_interval"}


@app.get("/api/settings/server")
def get_server_settings(user: dict = Depends(get_current_user)):
    """Get server config: editable settings + read-only reference values."""
    all_s = _settings_db.get_all_settings()
    editable = {k: all_s[k] for k in _EDITABLE_SERVER_SETTINGS if k in all_s}
    read_only = {
        "grpc_port": _settings.grpc_port,
        "http_port": _settings.http_port,
        "neo4j_uri": _settings.neo4j_uri,
    }
    return {"editable": editable, "read_only": read_only}


@app.put("/api/settings/server")
def update_server_settings(body: dict, user: dict = Depends(get_current_user)):
    """Update editable server settings."""
    updated = []
    for key, value in body.items():
        if key in _EDITABLE_SERVER_SETTINGS:
            _settings_db.set_setting(key, str(value))
            updated.append(key)
    return {"updated": updated}


# ── Agent default settings endpoints (JWT required) ──


@app.get("/api/settings/agent-defaults")
def get_agent_defaults(user: dict = Depends(get_current_user)):
    """Get agent default configuration."""
    return _settings_db.get_agent_defaults()


@app.put("/api/settings/agent-defaults")
def update_agent_defaults(body: dict, user: dict = Depends(get_current_user)):
    """Update agent default configuration."""
    updated = []
    for key, value in body.items():
        _settings_db.set_agent_default(key, str(value))
        updated.append(key)
    return {"updated": updated}


# ── Tag-based policy endpoints (JWT required) ──


class CreateTagRequest(BaseModel):
    tag_name: str
    description: str = ""
    color: str = "#3b82f6"
    priority: int = 0


class UpdateTagRequest(BaseModel):
    description: str | None = None
    color: str | None = None
    priority: int | None = None


class TagPolicyRequest(BaseModel):
    overrides: dict[str, str] = {}
    rules: list[dict] = []


class AssignTagRequest(BaseModel):
    tag_name: str


@app.get("/api/settings/tags")
def list_tags(user: dict = Depends(get_current_user)):
    """List all tags with agent counts."""
    return _settings_db.list_tags()


@app.post("/api/settings/tags")
def create_tag(body: CreateTagRequest, user: dict = Depends(get_current_user)):
    """Create a new tag."""
    try:
        return _settings_db.create_tag(
            body.tag_name, description=body.description, color=body.color, priority=body.priority,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=409, detail="Tag already exists") from e


@app.get("/api/settings/tags/{tag_name}")
def get_tag(tag_name: str, user: dict = Depends(get_current_user)):
    """Get tag detail."""
    tag = _settings_db.get_tag(tag_name)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return tag


@app.put("/api/settings/tags/{tag_name}")
def update_tag(tag_name: str, body: UpdateTagRequest, user: dict = Depends(get_current_user)):
    """Update tag metadata."""
    ok = _settings_db.update_tag(tag_name, description=body.description, color=body.color, priority=body.priority)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag not found")
    return {"status": "updated"}


@app.delete("/api/settings/tags/{tag_name}")
def delete_tag(tag_name: str, user: dict = Depends(get_current_user)):
    """Delete tag (cascades to assignments and policies)."""
    ok = _settings_db.delete_tag(tag_name)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag not found")
    return {"status": "deleted"}


@app.get("/api/settings/tags/{tag_name}/policy")
def get_tag_policy(tag_name: str, user: dict = Depends(get_current_user)):
    """Get policy overrides and rules for a tag."""
    tag = _settings_db.get_tag(tag_name)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    return {
        "overrides": _settings_db.get_tag_policy(tag_name),
        "rules": _settings_db.get_tag_rules(tag_name),
    }


@app.put("/api/settings/tags/{tag_name}/policy")
def set_tag_policy(tag_name: str, body: TagPolicyRequest, user: dict = Depends(get_current_user)):
    """Set policy overrides and rules for a tag."""
    try:
        _settings_db.set_tag_policy(tag_name, body.overrides)
        _settings_db.set_tag_rules(tag_name, body.rules)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {"status": "updated"}


@app.get("/api/fleet/agents/{agent_id}/tags")
def get_agent_tags(agent_id: str, user: dict = Depends(get_current_user)):
    """Get tags assigned to an agent."""
    return _settings_db.get_agent_tags(agent_id)


@app.post("/api/fleet/agents/{agent_id}/tags")
def assign_agent_tag(agent_id: str, body: AssignTagRequest, user: dict = Depends(get_current_user)):
    """Assign a tag to an agent."""
    try:
        _settings_db.assign_tag(agent_id, body.tag_name, assigned_by=user["sub"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "assigned"}


@app.delete("/api/fleet/agents/{agent_id}/tags/{tag_name}")
def remove_agent_tag(agent_id: str, tag_name: str, user: dict = Depends(get_current_user)):
    """Remove a tag from an agent."""
    ok = _settings_db.remove_tag(agent_id, tag_name)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag assignment not found")
    return {"status": "removed"}


@app.get("/api/fleet/agents/{agent_id}/resolved-config")
def get_resolved_config(agent_id: str, user: dict = Depends(get_current_user)):
    """Preview the resolved config for an agent (global defaults + tag overrides)."""
    return _settings_db.resolve_agent_config(agent_id)


# ── Threat Intel endpoints (JWT required) ──


@app.get("/api/threat-intel/rules")
def get_threat_intel_rules(user: dict = Depends(get_current_user)):
    """Get compiled Sigma rules from the threat intel blocklist."""
    from pathlib import Path

    import yaml

    yaml_path = Path(__file__).parent.parent / "rules" / "defaults" / "stage2_blocklist.yml"
    if not yaml_path.exists():
        return {"metadata": {}, "rules": []}

    with open(yaml_path) as fh:
        doc = yaml.safe_load(fh)

    return {
        "metadata": doc.get("metadata", {}),
        "rules": doc.get("rules", []),
    }


# ── Health check (no auth) ──


@app.get("/health")
async def health():
    return {"status": "ok"}
