"""Pydantic models for graph nodes and findings."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class UserNode(BaseModel):
    id: str  # username or uid
    name: str | None = None
    uid: str | None = None
    first_seen: datetime
    last_seen: datetime


class ProcessNode(BaseModel):
    id: str  # "hostname:pid:start_time"
    name: str
    pid: int
    cmd_line: str | None = None
    exe_path: str | None = None
    hostname: str
    start_time: datetime | None = None
    parent_pid: int | None = None
    bundle_id: str | None = None
    code_signed: bool | None = None
    signing_authority: str | None = None


class IpNode(BaseModel):
    id: str  # IP address string
    address: str
    is_private: bool
    first_seen: datetime
    last_seen: datetime
    country: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_hosting: bool = False
    is_proxy: bool = False
    classification: str = "unclassified"
    provider_name: str = ""
    reverse_dns: str = ""


class DomainNode(BaseModel):
    id: str  # domain name
    name: str
    first_seen: datetime
    last_seen: datetime
    is_dga_candidate: bool = False
    tld: str = ""


class FileNode(BaseModel):
    id: str  # normalized file path
    path: str
    hash_sha256: str | None = None
    size: int | None = None
    first_seen: datetime
    last_seen: datetime


class RegistryKeyNode(BaseModel):
    id: str  # full registry path + value_name
    path: str
    value_name: str | None = None
    value_data: str | None = None
    previous_data: str | None = None
    first_seen: datetime
    last_seen: datetime


class ChainStep(BaseModel):
    """One step in an event chain, stored as JSON in the findings table."""

    entity_type: str  # "user", "process", "ip"
    entity_id: str
    entity_name: str
    pid: int | None = None
    timestamp: datetime | None = None


class SecurityFinding(BaseModel):
    id: str  # UUID
    timestamp: datetime
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    affected_entities: list[str]
    evidence_event_ids: list[int]
    recommendation: str
    chain: list[ChainStep]
    affected_pids: list[int] = []
    iocs: dict = {}  # {"domains": [], "ips": [], "files": [], "urls": []}
    trigger_pid: int | None = None
    trigger_timestamp: datetime | None = None
