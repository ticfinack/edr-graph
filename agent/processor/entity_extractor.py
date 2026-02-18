"""Extract graph entities (User, Process, IP, Domain, File, RegistryKey) from OCSF events."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime

from agent import metrics
from agent.analysis.dga_detector import analyze_domain
from agent.analysis.persistence_detector import check_persistence

from agent.schema.graph_types import (
    DomainNode,
    FileNode,
    IpNode,
    ProcessNode,
    RegistryKeyNode,
    UserNode,
)
from agent.schema.ocsf_types import (
    Authentication,
    DnsActivity,
    FileActivity,
    NetworkActivity,
    OcsfEvent,
    ProcessActivity,
    RegistryActivity,
)

# Lazy import to avoid circular deps and allow graceful degradation
_get_process_identity = None

def _ensure_identity_import():
    global _get_process_identity
    if _get_process_identity is None:
        try:
            from agent.enrichment.process_identity import get_process_identity
            _get_process_identity = get_process_identity
        except ImportError:
            _get_process_identity = False  # Mark as unavailable

def _enrich_process_node(proc_node: ProcessNode, pid: int) -> None:
    """Enrich a ProcessNode with identity information if available."""
    _ensure_identity_import()
    if not _get_process_identity or not proc_node.exe_path:
        return
    try:
        identity = _get_process_identity(pid, proc_node.exe_path)
        proc_node.bundle_id = identity.bundle_id
        proc_node.code_signed = identity.code_signed
        proc_node.signing_authority = identity.signing_authority
    except Exception:
        logger.debug("Failed to enrich process identity for pid %d", pid, exc_info=True)


class ExtractedEntities:
    """Container for entities extracted from a single event."""

    def __init__(self) -> None:
        self.users: list[UserNode] = []
        self.processes: list[ProcessNode] = []
        self.ips: list[IpNode] = []
        self.domains: list[DomainNode] = []
        self.files: list[FileNode] = []
        self.registry_keys: list[RegistryKeyNode] = []
        self.spawned_edges: list[dict] = []  # {user_id, process_id, timestamp, activity_id}
        self.connected_edges: list[dict] = []  # {process_id, ip_id, timestamp, dst_port, protocol, direction}
        self.resolved_edges: list[dict] = []  # {process_id, domain_id, timestamp}
        self.resolves_to_edges: list[dict] = []  # {domain_id, ip_id, timestamp}
        self.file_edges: list[dict] = []  # {process_id, file_id, operation, timestamp}
        self.registry_edges: list[dict] = []  # {process_id, registry_id, operation, timestamp}
        self.risk_indicators: list[dict] = []  # persistence detections, DGA results, etc.


logger = logging.getLogger(__name__)


def extract_entities(
    event: OcsfEvent,
    event_id: int,
    dga_allowlist: set[str] | None = None,
    dga_threshold: float = 0.6,
    port_mapper=None,
) -> ExtractedEntities:
    """Extract nodes and edges from a normalized OCSF event."""
    entities = ExtractedEntities()
    now = event.time

    if isinstance(event, ProcessActivity):
        _extract_process_activity(event, event_id, entities, now)
    elif isinstance(event, NetworkActivity):
        _extract_network_activity(event, event_id, entities, now, port_mapper=port_mapper)
    elif isinstance(event, Authentication):
        _extract_authentication(event, event_id, entities, now)
    elif isinstance(event, DnsActivity):
        _extract_dns_activity(event, event_id, entities, now, dga_allowlist, dga_threshold)
    elif isinstance(event, FileActivity):
        _extract_file_activity(event, event_id, entities, now)
    elif isinstance(event, RegistryActivity):
        _extract_registry_activity(event, event_id, entities, now)

    # Run persistence detection on file and registry events
    if isinstance(event, (FileActivity, RegistryActivity)):
        persistence = check_persistence(event)
        if persistence:
            logger.warning(
                "Persistence detected: %s (%s) - %s",
                persistence.persistence_type,
                persistence.mitre_technique,
                persistence.path,
            )
            metrics.persistence_detections_total.labels(
                persistence_type=persistence.persistence_type,
            ).inc()
            entities.risk_indicators.append({
                "type": "persistence",
                "persistence_type": persistence.persistence_type,
                "platform": persistence.platform,
                "severity": persistence.severity,
                "mitre_technique": persistence.mitre_technique,
                "description": persistence.description,
                "path": persistence.path,
            })

    return entities


def _extract_process_activity(
    event: ProcessActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
) -> None:
    proc = event.process
    hostname = event.device.hostname

    start_time = proc.created_time or now
    proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"

    proc_node = ProcessNode(
        id=proc_id,
        name=proc.name,
        pid=proc.pid,
        cmd_line=proc.cmd_line or None,
        exe_path=proc.exe_path or None,
        hostname=hostname,
        start_time=start_time,
    )
    _enrich_process_node(proc_node, proc.pid)
    entities.processes.append(proc_node)

    if event.actor and event.actor.user:
        user = event.actor.user
        user_id = user.name or user.uid or "unknown"
        entities.users.append(
            UserNode(
                id=user_id,
                name=user.name,
                uid=user.uid or None,
                first_seen=now,
                last_seen=now,
            )
        )
        entities.spawned_edges.append(
            {
                "user_id": user_id,
                "process_id": proc_id,
                "timestamp": now,
                "activity_id": event.activity_id,
                "event_id": event_id,
            }
        )


def _extract_network_activity(
    event: NetworkActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
    port_mapper=None,
) -> None:
    if event.process:
        proc = event.process
        hostname = event.device.hostname
        start_time = proc.created_time or now
        proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"

        proc_node = ProcessNode(
            id=proc_id,
            name=proc.name,
            pid=proc.pid,
            cmd_line=proc.cmd_line or None,
            exe_path=proc.exe_path or None,
            hostname=hostname,
            start_time=start_time,
        )
        _enrich_process_node(proc_node, proc.pid)
        entities.processes.append(proc_node)

        if event.dst_endpoint and event.dst_endpoint.ip:
            ip_addr = event.dst_endpoint.ip
            dst_port = event.dst_endpoint.port
            is_private = _is_private_ip(ip_addr)
            entities.ips.append(
                IpNode(
                    id=ip_addr,
                    address=ip_addr,
                    is_private=is_private,
                    first_seen=now,
                    last_seen=now,
                )
            )
            entities.connected_edges.append(
                {
                    "process_id": proc_id,
                    "ip_id": ip_addr,
                    "timestamp": now,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "direction": "outbound",
                    "event_id": event_id,
                }
            )

            # Port mapper enrichment: add connection context
            if port_mapper is not None and dst_port is not None:
                try:
                    src_identity = None
                    if proc_node.code_signed is not None:
                        # Build a minimal identity from proc_node fields
                        from agent.enrichment.process_identity import ProcessIdentity
                        src_identity = ProcessIdentity(
                            pid=proc.pid,
                            path=proc.exe_path or "",
                            name=proc.name,
                            bundle_id=proc_node.bundle_id,
                            code_signed=proc_node.code_signed or False,
                            signing_authority=proc_node.signing_authority,
                        )
                    conn_ctx = port_mapper.build_connection_context(
                        src_pid=proc.pid,
                        src_name=proc.name,
                        src_identity=src_identity,
                        dst_ip=ip_addr,
                        dst_port=dst_port,
                    )
                    if conn_ctx.is_localhost_ipc:
                        if conn_ctx.dest_process:
                            entities.risk_indicators.append({
                                "type": "connection_context",
                                "description": f"Localhost IPC: {proc.name} -> {conn_ctx.dest_process} (low risk)",
                                "severity": "info",
                                "connection_context": conn_ctx.connection_description,
                            })
                        else:
                            entities.risk_indicators.append({
                                "type": "connection_context",
                                "description": f"Localhost connection to unknown listener on port {dst_port}",
                                "severity": "low",
                                "connection_context": conn_ctx.connection_description,
                            })
                except Exception:
                    logger.debug("Port mapper enrichment failed", exc_info=True)


def _extract_authentication(
    event: Authentication,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
) -> None:
    user_id = event.user.name or "unknown"
    entities.users.append(
        UserNode(
            id=user_id,
            name=event.user.name,
            uid=event.user.uid or None,
            first_seen=now,
            last_seen=now,
        )
    )

    if event.src_endpoint and event.src_endpoint.ip:
        ip_addr = event.src_endpoint.ip
        entities.ips.append(
            IpNode(
                id=ip_addr,
                address=ip_addr,
                is_private=_is_private_ip(ip_addr),
                first_seen=now,
                last_seen=now,
            )
        )


def _extract_dns_activity(
    event: DnsActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
    dga_allowlist: set[str] | None = None,
    dga_threshold: float = 0.6,
) -> None:
    hostname = event.device.hostname
    proc_id = None

    if event.process:
        proc = event.process
        start_time = proc.created_time or now
        proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"
        entities.processes.append(
            ProcessNode(
                id=proc_id,
                name=proc.name,
                pid=proc.pid,
                cmd_line=proc.cmd_line or None,
                exe_path=proc.exe_path or None,
                hostname=hostname,
                start_time=start_time,
            )
        )

    if event.query_domain:
        domain_name = event.query_domain.lower().rstrip(".")
        tld = domain_name.rsplit(".", 1)[-1] if "." in domain_name else ""

        # Run DGA detection
        dga_result = analyze_domain(
            domain_name,
            threshold=dga_threshold,
            allowlist=dga_allowlist,
        )
        is_dga = dga_result.is_dga_candidate
        if is_dga:
            logger.warning(
                "DGA candidate detected: %s (score: %.2f, reasons: %s)",
                domain_name,
                dga_result.score,
                ", ".join(dga_result.reasons),
            )
            metrics.dga_detections_total.inc()

        entities.domains.append(
            DomainNode(
                id=domain_name,
                name=domain_name,
                first_seen=now,
                last_seen=now,
                is_dga_candidate=is_dga,
                tld=tld,
            )
        )

        if proc_id:
            entities.resolved_edges.append(
                {
                    "process_id": proc_id,
                    "domain_id": domain_name,
                    "timestamp": now,
                    "event_id": event_id,
                }
            )

        # Create Domain->IP edges for resolved IPs
        for ip_addr in event.resolved_ips:
            ip_addr = ip_addr.strip()
            if not ip_addr:
                continue
            entities.ips.append(
                IpNode(
                    id=ip_addr,
                    address=ip_addr,
                    is_private=_is_private_ip(ip_addr),
                    first_seen=now,
                    last_seen=now,
                )
            )
            entities.resolves_to_edges.append(
                {
                    "domain_id": domain_name,
                    "ip_id": ip_addr,
                    "timestamp": now,
                    "event_id": event_id,
                }
            )


def _extract_file_activity(
    event: FileActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
) -> None:
    hostname = event.device.hostname
    proc_id = None

    if event.process:
        proc = event.process
        start_time = proc.created_time or now
        proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"
        entities.processes.append(
            ProcessNode(
                id=proc_id,
                name=proc.name,
                pid=proc.pid,
                cmd_line=proc.cmd_line or None,
                exe_path=proc.exe_path or None,
                hostname=hostname,
                start_time=start_time,
            )
        )

    if event.file_path:
        file_id = event.file_path

        entities.files.append(
            FileNode(
                id=file_id,
                path=event.file_path,
                hash_sha256=event.file_hash_sha256,
                size=event.file_size,
                first_seen=now,
                last_seen=now,
            )
        )

        # Map activity_id to operation name
        op_map = {1: "CREATED", 2: "READ", 3: "MODIFIED", 4: "DELETED"}
        operation = op_map.get(event.activity_id, "MODIFIED")

        if proc_id:
            entities.file_edges.append(
                {
                    "process_id": proc_id,
                    "file_id": file_id,
                    "operation": operation,
                    "timestamp": now,
                    "event_id": event_id,
                }
            )


def _extract_registry_activity(
    event: RegistryActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
) -> None:
    hostname = event.device.hostname
    proc_id = None

    if event.process:
        proc = event.process
        start_time = proc.created_time or now
        proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"
        entities.processes.append(
            ProcessNode(
                id=proc_id,
                name=proc.name,
                pid=proc.pid,
                cmd_line=proc.cmd_line or None,
                exe_path=proc.exe_path or None,
                hostname=hostname,
                start_time=start_time,
            )
        )

    if event.reg_path:
        # Use path + value_name as unique ID
        reg_id = event.reg_path
        if event.reg_value_name:
            reg_id = f"{event.reg_path}\\{event.reg_value_name}"

        entities.registry_keys.append(
            RegistryKeyNode(
                id=reg_id,
                path=event.reg_path,
                value_name=event.reg_value_name,
                value_data=event.reg_value_data,
                previous_data=event.reg_previous_data,
                first_seen=now,
                last_seen=now,
            )
        )

        op_map = {1: "CREATED", 3: "MODIFIED", 4: "DELETED"}
        operation = op_map.get(event.activity_id, "MODIFIED")

        if proc_id:
            entities.registry_edges.append(
                {
                    "process_id": proc_id,
                    "registry_id": reg_id,
                    "operation": operation,
                    "timestamp": now,
                    "event_id": event_id,
                }
            )


def _is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False
