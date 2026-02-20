"""Pydantic models for OCSF-normalized events."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class OcsfMetadata(BaseModel):
    version: str = "1.1.0"
    product: str = "edr-graph"
    original_time: datetime | None = None
    log_source: str = ""


class DeviceInfo(BaseModel):
    hostname: str
    os_name: str = ""


class UserInfo(BaseModel):
    name: str
    uid: str = ""


class ActorInfo(BaseModel):
    user: UserInfo


class ProcessInfo(BaseModel):
    pid: int
    name: str
    cmd_line: str = ""
    exe_path: str = ""
    parent_pid: int | None = None
    created_time: datetime | None = None


class NetworkEndpoint(BaseModel):
    ip: str = ""
    port: int = 0
    hostname: str = ""


class ProcessActivity(BaseModel):
    class_uid: int = 1007
    category_uid: int = 1
    activity_id: int  # 1=Launch, 2=Terminate
    severity_id: int = 1
    time: datetime
    actor: ActorInfo | None = None
    process: ProcessInfo
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


class NetworkActivity(BaseModel):
    class_uid: int = 4001
    category_uid: int = 4
    activity_id: int  # 1=Open, 2=Close, 6=Traffic
    severity_id: int = 1
    time: datetime
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    process: ProcessInfo | None = None
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


class Authentication(BaseModel):
    class_uid: int = 3002
    category_uid: int = 3
    activity_id: int  # 1=Logon, 2=Logoff
    status_id: int  # 1=Success, 2=Failure
    severity_id: int = 1
    time: datetime
    user: UserInfo
    src_endpoint: NetworkEndpoint | None = None
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


class DnsActivity(BaseModel):
    """OCSF DNS Activity (class 4003)."""

    class_uid: int = 4003
    category_uid: int = 4
    activity_id: int = 1  # 1=Query
    severity_id: int = 1
    time: datetime
    process: ProcessInfo | None = None
    query_domain: str = ""
    resolved_ips: list[str] = []
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


class FileActivity(BaseModel):
    """OCSF File Activity (class 1001)."""

    class_uid: int = 1001
    category_uid: int = 1
    activity_id: int  # 1=Create, 2=Read, 3=Update/Modify, 4=Delete
    severity_id: int = 1
    time: datetime
    process: ProcessInfo | None = None
    file_path: str = ""
    file_hash_sha256: str | None = None
    file_size: int | None = None
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


class RegistryActivity(BaseModel):
    """OCSF Registry Activity (class 201001, custom)."""

    class_uid: int = 201001
    category_uid: int = 1
    activity_id: int  # 1=Create, 3=Modify, 4=Delete
    severity_id: int = 1
    time: datetime
    process: ProcessInfo | None = None
    reg_path: str = ""
    reg_value_name: str | None = None
    reg_value_data: str | None = None
    reg_previous_data: str | None = None
    device: DeviceInfo
    metadata: OcsfMetadata = OcsfMetadata()


# Union type for all OCSF events
OcsfEvent = ProcessActivity | NetworkActivity | Authentication | DnsActivity | FileActivity | RegistryActivity
