"""Fleet management dashboard REST API.

Provides endpoints for viewing connected agents, recent findings,
cross-host correlation, lateral/vertical movement detection,
SOC dashboard authentication, user management, and settings.
"""

from __future__ import annotations

import json
import secrets
import time

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel

from server.auth import get_current_user
from server.neo4j_client import Neo4jClient
from server.settings_db import _VALID_AGENT_SETTINGS, SettingsDB

_VALID_ROLES = {"admin", "viewer"}


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Require admin role for write/mutate endpoints."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

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


_feed_manager = None
_diamond_investigator = None


def set_feed_manager(fm) -> None:
    global _feed_manager
    _feed_manager = fm


def set_diamond_investigator(di) -> None:
    global _diamond_investigator
    _diamond_investigator = di


def verify_agent_token(request: Request) -> str:
    """FastAPI dependency: verify agent registration_key from Bearer token.

    Returns the registration key on success. Raises 401/403 on failure.
    Used for machine-to-machine endpoints (intel-bundle).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth[7:]
    if not _settings_db:
        raise HTTPException(status_code=503, detail="Settings database unavailable")
    valid, reason = _settings_db.check_key_status(token)
    if not valid:
        raise HTTPException(status_code=403, detail=reason)
    return token


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
    detail = _neo4j.get_lateral_movement_detail(finding_id, settings_db=_settings_db)
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


@app.get("/api/fleet/incidents")
def list_incidents(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    user: dict = Depends(get_current_user),
):
    """List incidents with status, hosts, pivot IP, follow-on count."""
    return _neo4j.list_incidents(status=status, limit=limit)


@app.get("/api/fleet/incidents/{incident_id}")
def incident_detail(incident_id: str, user: dict = Depends(get_current_user)):
    """Full incident detail: stitched chains + follow-on finding list + Diamond assessment."""
    detail = _neo4j.get_incident_detail(incident_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Incident not found")
    # Enrich with Diamond assessment from SQLite
    assessment = _settings_db.get_latest_diamond_assessment(incident_id)
    if assessment:
        try:
            detail["diamond_assessment"] = json.loads(assessment["assessment_json"])
        except (json.JSONDecodeError, TypeError):
            detail["diamond_assessment"] = None
        detail["diamond_assessed_at"] = assessment["assessed_at"]
    return detail


@app.post("/api/fleet/incidents/{incident_id}/close")
def close_incident(incident_id: str, user: dict = Depends(require_admin)):
    """Admin closes an incident (stops follow-on tagging, clears surveillance)."""
    detail = _neo4j.get_incident_detail(incident_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Incident not found")
    _neo4j.update_incident_status(incident_id, "closed")
    return {"status": "closed"}


def _extract_chain_pids(chain: list[dict]) -> list[int]:
    """Extract unique process PIDs from chain step data."""
    return list({step["pid"] for step in chain
                 if step.get("entity_type") == "process" and step.get("pid", 0) > 0})


def _extract_chain_usernames(chain: list[dict]) -> list[str]:
    """Extract unique usernames from chain step data."""
    return list({step["entity_name"] for step in chain
                 if step.get("entity_type") == "user" and step.get("entity_name")})


@app.post("/api/fleet/incidents/{incident_id}/pull-surveillance")
def pull_surveillance_logs(incident_id: str, user: dict = Depends(require_admin)):
    """Enqueue pull_surveillance_logs XDR query on both src/dst agents.

    For active incidents, autonomous collection is handled by XdrOrchestrator;
    manual pulls are only needed for non-active incidents.
    """
    import json
    import uuid

    detail = _neo4j.get_incident_detail(incident_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Incident not found")

    if detail.get("status") == "active":
        return {"message": "Auto-collection is active"}

    src_agent = detail.get("src_agent_id", "")
    dst_agent = detail.get("dst_agent_id", "")
    pivot_ip = detail.get("pivot_ip", "")
    src_ips = _neo4j.get_incident_src_ips(incident_id)

    # Extract anchor PIDs and usernames from chain data
    src_pids = _extract_chain_pids(detail.get("source_chain", []))
    dst_pids = _extract_chain_pids(detail.get("target_chain", []))
    src_users = _extract_chain_usernames(detail.get("source_chain", []))
    dst_users = _extract_chain_usernames(detail.get("target_chain", []))

    enqueued = []
    # Pull from target (dst) agent — surveillance of source IPs + target PIDs + target usernames
    if dst_agent and (src_ips or dst_pids or dst_users):
        qid = str(uuid.uuid4())
        _settings_db.enqueue_xdr_query(
            qid, dst_agent,
            f"{incident_id}:surv_dst",
            "pull_surveillance_logs",
            json.dumps({"ips": src_ips, "anchor_pids": dst_pids, "usernames": dst_users, "limit": 200}),
        )
        enqueued.append({"query_id": qid, "agent_id": dst_agent, "ips": src_ips})

    # Pull from source agent — surveillance of pivot IP + source PIDs + source usernames
    if src_agent and (pivot_ip or src_pids or src_users):
        qid = str(uuid.uuid4())
        _settings_db.enqueue_xdr_query(
            qid, src_agent,
            f"{incident_id}:surv_src",
            "pull_surveillance_logs",
            json.dumps({"ips": [pivot_ip] if pivot_ip else [], "anchor_pids": src_pids, "usernames": src_users, "limit": 200}),
        )
        enqueued.append({"query_id": qid, "agent_id": src_agent, "ips": [pivot_ip] if pivot_ip else []})

    return {"enqueued": enqueued}


@app.get("/api/fleet/incidents/{incident_id}/surveillance-logs")
def get_surveillance_logs(incident_id: str, user: dict = Depends(get_current_user)):
    """Return surveillance logs for an incident from the persistent store."""
    logs = _settings_db.get_surveillance_logs(incident_id)
    dst_logs = logs.get("dst_logs", [])
    src_logs = logs.get("src_logs", [])

    # Determine status: 'completed' if logs exist, 'collecting' if orchestrator
    # is actively pulling, 'not_requested' otherwise
    def _side_status(side_logs: list, side: str) -> str:
        if side_logs:
            return "completed"
        # Check if there's a pending pull
        if _settings_db.has_pending_xdr_query(
            f"{incident_id}:surv_{side}", "pull_surveillance_logs",
        ):
            return "collecting"
        # Check if we've ever enqueued a pull for this side
        state = _settings_db.get_surveillance_pull_state(incident_id, side)
        if state["last_enqueue_at"] > 0:
            return "collecting"
        return "not_requested"

    return {
        "dst_logs": dst_logs,
        "src_logs": src_logs,
        "dst_status": _side_status(dst_logs, "dst"),
        "src_status": _side_status(src_logs, "src"),
    }


@app.get("/api/fleet/incidents/{incident_id}/ocsf-evidence")
def get_ocsf_evidence(
    incident_id: str,
    event_type: str | None = Query(default=None),
    limit: int = Query(default=500, le=1000),
    user: dict = Depends(get_current_user),
):
    """Return OCSF evidence for an incident, optionally filtered by event_type."""
    evidence = _settings_db.get_ocsf_evidence(incident_id, limit=limit)
    if event_type:
        evidence = [e for e in evidence if e.get("event_type") == event_type]
    return {"evidence": evidence, "total": len(evidence)}


@app.get("/api/fleet/incidents/{incident_id}/diamond-assessment")
def get_diamond_assessment(incident_id: str, user: dict = Depends(get_current_user)):
    """Return the latest Diamond Model assessment or pending status."""
    assessment = _settings_db.get_latest_diamond_assessment(incident_id)
    if not assessment:
        return {"status": "pending"}
    try:
        parsed = json.loads(assessment["assessment_json"])
    except (json.JSONDecodeError, TypeError):
        parsed = None
    return {
        "status": "completed",
        "assessment": parsed,
        "model_name": assessment["model_name"],
        "assessed_at": assessment["assessed_at"],
        "prompt_tokens": assessment["prompt_tokens"],
        "completion_tokens": assessment["completion_tokens"],
    }


@app.post("/api/fleet/incidents/{incident_id}/reassess")
def reassess_incident(incident_id: str, user: dict = Depends(require_admin)):
    """Admin-triggered re-assessment of an incident's Diamond Model analysis."""
    if _diamond_investigator is None:
        raise HTTPException(status_code=503, detail="Diamond investigator not configured (no API key)")
    detail = _neo4j.get_incident_detail(incident_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = _diamond_investigator.assess_incident(incident_id)
    if result is None:
        raise HTTPException(status_code=500, detail="Assessment failed")
    return {"status": "completed", "assessment": result}


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
def create_registration_key(body: CreateKeyRequest, user: dict = Depends(require_admin)):
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
def revoke_registration_key(key: str, user: dict = Depends(require_admin)):
    """Revoke a registration key."""
    ok = _settings_db.revoke_registration_key(key, revoked_by=user["sub"])
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "revoked"}


@app.delete("/api/fleet/registration-keys/{key}")
def delete_registration_key(key: str, user: dict = Depends(require_admin)):
    """Permanently delete a registration key."""
    ok = _settings_db.delete_registration_key(key)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "deleted"}


# ── User management endpoints (JWT required) ──


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    password: str | None = None
    role: str | None = None


@app.get("/api/settings/users")
def list_users(user: dict = Depends(get_current_user)):
    """List all users (no password_hash)."""
    return _settings_db.list_users()


@app.post("/api/settings/users")
def create_user(body: CreateUserRequest, user: dict = Depends(require_admin)):
    """Create a new user."""
    from server.auth import hash_password

    if body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {body.role!r}. Must be one of {sorted(_VALID_ROLES)}")
    if _settings_db.get_user(body.username):
        raise HTTPException(status_code=409, detail="User already exists")
    return _settings_db.create_user(body.username, hash_password(body.password), role=body.role)


@app.put("/api/settings/users/{username}")
def update_user(username: str, body: UpdateUserRequest, user: dict = Depends(require_admin)):
    """Update a user's password and/or role."""
    from server.auth import hash_password

    pw_hash = hash_password(body.password) if body.password else None
    ok = _settings_db.update_user(username, password_hash=pw_hash, role=body.role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "updated"}


@app.delete("/api/settings/users/{username}")
def delete_user(username: str, user: dict = Depends(require_admin)):
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
def update_server_settings(body: dict, user: dict = Depends(require_admin)):
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
def update_agent_defaults(body: dict, user: dict = Depends(require_admin)):
    """Update agent default configuration."""
    updated = []
    skipped = []
    for key, value in body.items():
        if key not in _VALID_AGENT_SETTINGS:
            skipped.append(key)
            continue
        _settings_db.set_agent_default(key, str(value))
        updated.append(key)
    return {"updated": updated, "skipped": skipped}


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
def create_tag(body: CreateTagRequest, user: dict = Depends(require_admin)):
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
def update_tag(tag_name: str, body: UpdateTagRequest, user: dict = Depends(require_admin)):
    """Update tag metadata."""
    ok = _settings_db.update_tag(tag_name, description=body.description, color=body.color, priority=body.priority)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag not found")
    return {"status": "updated"}


@app.delete("/api/settings/tags/{tag_name}")
def delete_tag(tag_name: str, user: dict = Depends(require_admin)):
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
def set_tag_policy(tag_name: str, body: TagPolicyRequest, user: dict = Depends(require_admin)):
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
def assign_agent_tag(agent_id: str, body: AssignTagRequest, user: dict = Depends(require_admin)):
    """Assign a tag to an agent."""
    try:
        _settings_db.assign_tag(agent_id, body.tag_name, assigned_by=user["sub"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"status": "assigned"}


@app.delete("/api/fleet/agents/{agent_id}/tags/{tag_name}")
def remove_agent_tag(agent_id: str, tag_name: str, user: dict = Depends(require_admin)):
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


# ── Global Custom Rules CRUD ──


class GlobalRuleRequest(BaseModel):
    action: str
    stage: str
    rule_type: str
    pattern: str
    chain_filter: str = ""
    description: str = ""


@app.get("/api/threat-intel/custom-rules")
def list_custom_rules(user: dict = Depends(get_current_user)):
    return _settings_db.list_global_custom_rules()


@app.post("/api/threat-intel/custom-rules")
def add_custom_rule(body: GlobalRuleRequest, user: dict = Depends(require_admin)):
    try:
        rule_id = _settings_db.add_global_custom_rule(
            action=body.action,
            stage=body.stage,
            rule_type=body.rule_type,
            pattern=body.pattern,
            chain_filter=body.chain_filter,
            description=body.description,
            created_by=user.get("sub", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"id": rule_id, "status": "created"}


@app.delete("/api/threat-intel/custom-rules/{rule_id}")
def delete_custom_rule(rule_id: int, user: dict = Depends(require_admin)):
    ok = _settings_db.delete_global_custom_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted"}


# ── Global Intel Suppressions CRUD ──


class SuppressionRequest(BaseModel):
    indicator_type: str
    pattern: str
    reason: str = ""


@app.get("/api/threat-intel/suppressions")
def list_suppressions(user: dict = Depends(get_current_user)):
    return _settings_db.list_global_intel_suppressions()


@app.post("/api/threat-intel/suppressions")
def add_suppression(body: SuppressionRequest, user: dict = Depends(require_admin)):
    try:
        row = _settings_db.add_global_intel_suppression(
            indicator_type=body.indicator_type,
            pattern=body.pattern,
            reason=body.reason,
            created_by=user.get("sub", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception:
        raise HTTPException(status_code=409, detail="Duplicate suppression") from None
    return row


@app.delete("/api/threat-intel/suppressions/{suppression_id}")
def delete_suppression(suppression_id: int, user: dict = Depends(require_admin)):
    ok = _settings_db.delete_global_intel_suppression(suppression_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Suppression not found")
    return {"status": "deleted"}


# ── Sigma Rule Toggle ──


@app.get("/api/threat-intel/sigma/disabled")
def list_disabled_sigma(user: dict = Depends(get_current_user)):
    return _settings_db.list_disabled_sigma_rules()


@app.post("/api/threat-intel/sigma/{rule_id:path}/toggle")
def toggle_sigma_rule(rule_id: str, user: dict = Depends(require_admin)):
    try:
        now_disabled = _settings_db.toggle_sigma_rule(rule_id, disabled_by=user.get("sub", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"rule_id": rule_id, "disabled": now_disabled}


# ── Agent IOC Summary (from heartbeat data) ──


@app.get("/api/threat-intel/agent-ioc-summary")
def get_agent_ioc_summary(user: dict = Depends(get_current_user)):
    agents = _neo4j.get_fleet_status()
    summaries = []
    for a in agents:
        ioc_json = a.get("ioc_stats_json")
        if ioc_json:
            try:
                stats = json.loads(ioc_json)
            except (json.JSONDecodeError, TypeError):
                continue
            summaries.append({
                "agent_id": a["agent_id"],
                "hostname": a["hostname"],
                "status": a["status"],
                **stats,
            })
    return summaries


# ── Centralized Intel Distribution ──


@app.get("/api/fleet/intel-bundle")
def get_intel_bundle(reg_key: str = Depends(verify_agent_token)):
    """Return aggregated IOC bundle as gzipped JSON.

    Secured with agent registration key (not user JWT).
    Returns 503 if the feed manager is still performing its initial download.
    """
    if _feed_manager is None:
        raise HTTPException(status_code=503, detail="Intel feed manager not initialized")
    bundle_bytes = _feed_manager.get_bundle_gzip()
    if not bundle_bytes:
        raise HTTPException(status_code=503, detail="Intel bundle compiling — try again shortly")
    return Response(
        content=bundle_bytes,
        media_type="application/json",
        headers={"Content-Encoding": "gzip"},
    )


@app.get("/api/threat-intel/feed-manager-stats")
def get_feed_manager_stats(user: dict = Depends(get_current_user)):
    """Get fleet feed manager statistics (upstream OSINT pull status)."""
    if _feed_manager is None:
        return {"status": "disabled", "ready": False}
    return _feed_manager.get_stats()


@app.get("/api/threat-intel/indicators")
def get_threat_intel_indicators(
    type: str = Query("ip", pattern="^(ip|domain|hash)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=500),
    q: str = Query("", max_length=200),
    feed: str = Query(""),
    user: dict = Depends(get_current_user),
):
    """Paginated, filterable indicator browser for the dashboard."""
    if _feed_manager is None:
        return {"items": [], "total": 0, "page": 1, "pages": 1}
    return _feed_manager.get_paginated_indicators(
        ioc_type=type, page=page, limit=limit, query=q, feed=feed,
    )


# ── Health check (no auth) ──


@app.get("/health")
async def health():
    return {"status": "ok"}
