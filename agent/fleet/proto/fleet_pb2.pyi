from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AgentInfo(_message.Message):
    __slots__ = ("agent_id", "hostname", "platform", "os_version", "agent_version", "ip_address", "registered_at", "ip_addresses", "public_ip")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    HOSTNAME_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    REGISTERED_AT_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_IP_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    hostname: str
    platform: str
    os_version: str
    agent_version: str
    ip_address: str
    registered_at: int
    ip_addresses: _containers.RepeatedScalarFieldContainer[str]
    public_ip: str
    def __init__(self, agent_id: _Optional[str] = ..., hostname: _Optional[str] = ..., platform: _Optional[str] = ..., os_version: _Optional[str] = ..., agent_version: _Optional[str] = ..., ip_address: _Optional[str] = ..., registered_at: _Optional[int] = ..., ip_addresses: _Optional[_Iterable[str]] = ..., public_ip: _Optional[str] = ...) -> None: ...

class ChainStep(_message.Message):
    __slots__ = ("entity_type", "entity_id", "entity_name", "pid", "timestamp")
    ENTITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    ENTITY_NAME_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    entity_type: str
    entity_id: str
    entity_name: str
    pid: int
    timestamp: int
    def __init__(self, entity_type: _Optional[str] = ..., entity_id: _Optional[str] = ..., entity_name: _Optional[str] = ..., pid: _Optional[int] = ..., timestamp: _Optional[int] = ...) -> None: ...

class SecurityFinding(_message.Message):
    __slots__ = ("id", "timestamp", "severity", "title", "description", "affected_entities", "evidence_event_ids", "recommendation", "chain", "affected_pids", "iocs_json")
    ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    AFFECTED_ENTITIES_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_EVENT_IDS_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDATION_FIELD_NUMBER: _ClassVar[int]
    CHAIN_FIELD_NUMBER: _ClassVar[int]
    AFFECTED_PIDS_FIELD_NUMBER: _ClassVar[int]
    IOCS_JSON_FIELD_NUMBER: _ClassVar[int]
    id: str
    timestamp: int
    severity: str
    title: str
    description: str
    affected_entities: _containers.RepeatedScalarFieldContainer[str]
    evidence_event_ids: _containers.RepeatedScalarFieldContainer[int]
    recommendation: str
    chain: _containers.RepeatedCompositeFieldContainer[ChainStep]
    affected_pids: _containers.RepeatedScalarFieldContainer[int]
    iocs_json: str
    def __init__(self, id: _Optional[str] = ..., timestamp: _Optional[int] = ..., severity: _Optional[str] = ..., title: _Optional[str] = ..., description: _Optional[str] = ..., affected_entities: _Optional[_Iterable[str]] = ..., evidence_event_ids: _Optional[_Iterable[int]] = ..., recommendation: _Optional[str] = ..., chain: _Optional[_Iterable[_Union[ChainStep, _Mapping]]] = ..., affected_pids: _Optional[_Iterable[int]] = ..., iocs_json: _Optional[str] = ...) -> None: ...

class OcsfEvent(_message.Message):
    __slots__ = ("class_uid", "event_json")
    CLASS_UID_FIELD_NUMBER: _ClassVar[int]
    EVENT_JSON_FIELD_NUMBER: _ClassVar[int]
    class_uid: int
    event_json: str
    def __init__(self, class_uid: _Optional[int] = ..., event_json: _Optional[str] = ...) -> None: ...

class RegisterAgentRequest(_message.Message):
    __slots__ = ("agent_info", "registration_key")
    AGENT_INFO_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_KEY_FIELD_NUMBER: _ClassVar[int]
    agent_info: AgentInfo
    registration_key: str
    def __init__(self, agent_info: _Optional[_Union[AgentInfo, _Mapping]] = ..., registration_key: _Optional[str] = ...) -> None: ...

class RegisterAgentResponse(_message.Message):
    __slots__ = ("accepted", "agent_id", "message")
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    accepted: bool
    agent_id: str
    message: str
    def __init__(self, accepted: bool = ..., agent_id: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class SendFindingsRequest(_message.Message):
    __slots__ = ("agent_id", "findings")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    findings: _containers.RepeatedCompositeFieldContainer[SecurityFinding]
    def __init__(self, agent_id: _Optional[str] = ..., findings: _Optional[_Iterable[_Union[SecurityFinding, _Mapping]]] = ...) -> None: ...

class SendFindingsResponse(_message.Message):
    __slots__ = ("accepted_count", "message")
    ACCEPTED_COUNT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    accepted_count: int
    message: str
    def __init__(self, accepted_count: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class SendEventsRequest(_message.Message):
    __slots__ = ("agent_id", "events")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    events: _containers.RepeatedCompositeFieldContainer[OcsfEvent]
    def __init__(self, agent_id: _Optional[str] = ..., events: _Optional[_Iterable[_Union[OcsfEvent, _Mapping]]] = ...) -> None: ...

class SendEventsResponse(_message.Message):
    __slots__ = ("accepted_count", "message")
    ACCEPTED_COUNT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    accepted_count: int
    message: str
    def __init__(self, accepted_count: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class HeartbeatRequest(_message.Message):
    __slots__ = ("agent_id", "timestamp", "queue_depth", "findings_count", "status", "clock_offset_ms", "ip_addresses", "public_ip", "query_results_json")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    QUEUE_DEPTH_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_COUNT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CLOCK_OFFSET_MS_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_IP_FIELD_NUMBER: _ClassVar[int]
    QUERY_RESULTS_JSON_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    timestamp: int
    queue_depth: int
    findings_count: int
    status: str
    clock_offset_ms: int
    ip_addresses: _containers.RepeatedScalarFieldContainer[str]
    public_ip: str
    query_results_json: str
    def __init__(self, agent_id: _Optional[str] = ..., timestamp: _Optional[int] = ..., queue_depth: _Optional[int] = ..., findings_count: _Optional[int] = ..., status: _Optional[str] = ..., clock_offset_ms: _Optional[int] = ..., ip_addresses: _Optional[_Iterable[str]] = ..., public_ip: _Optional[str] = ..., query_results_json: _Optional[str] = ...) -> None: ...

class HeartbeatResponse(_message.Message):
    __slots__ = ("acknowledged", "message", "config_json", "config_signature")
    ACKNOWLEDGED_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_JSON_FIELD_NUMBER: _ClassVar[int]
    CONFIG_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    acknowledged: bool
    message: str
    config_json: str
    config_signature: str
    def __init__(self, acknowledged: bool = ..., message: _Optional[str] = ..., config_json: _Optional[str] = ..., config_signature: _Optional[str] = ...) -> None: ...
