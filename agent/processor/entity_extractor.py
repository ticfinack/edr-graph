"""Extract graph entities (User, Process, IP, Domain, File, RegistryKey) from OCSF events."""

from __future__ import annotations

import contextlib
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


_ppid_cache: dict[int, int] = {}  # pid -> parent_pid, populated once per PID
_create_time_cache: dict[int, float] = {}  # pid -> create_time epoch, populated once per PID
_username_cache: dict[int, str] = {}  # pid -> username (empty string = unresolvable)
_name_cache: dict[int, str] = {}  # pid -> process_name, for fast-path enforcer chain building


def _resolve_start_time(pid: int, fallback: datetime) -> datetime:
    """Return a stable process creation time for the given PID.

    Uses psutil to look up the real process creation time and caches it.
    This ensures that all events referencing the same PID produce the same
    Process node ID, preventing duplicate nodes in the graph.

    Handles PID reuse: if the live process create_time differs from the
    cached value, the cache entry is refreshed (the old PID was recycled).

    Falls back to the provided timestamp only when the process is genuinely
    unknown (dead before we ever saw it).
    """
    if pid <= 0:
        return fallback

    try:
        import psutil

        p = psutil.Process(pid)
        ct = p.create_time()
        if ct and ct > 0:
            cached = _create_time_cache.get(pid)
            if cached is not None and cached > 0 and abs(cached - ct) < 1.0:
                # Same process, use cached value
                return datetime.fromtimestamp(cached)
            # New or changed — update cache (handles PID reuse)
            _create_time_cache[pid] = ct
            # Also invalidate ppid cache on PID reuse
            if cached is not None and cached > 0 and abs(cached - ct) >= 1.0:
                _ppid_cache.pop(pid, None)
                _name_cache.pop(pid, None)
            return datetime.fromtimestamp(ct)
    except Exception:
        pass

    # Process is dead — use cached value if we had one
    if pid in _create_time_cache:
        epoch = _create_time_cache[pid]
        if epoch > 0:
            return datetime.fromtimestamp(epoch)
        return fallback

    # Never seen this PID and it's already dead — mark unresolvable
    _create_time_cache[pid] = 0
    return fallback


def _enrich_process_node(proc_node: ProcessNode, pid: int) -> None:
    """Enrich a ProcessNode with identity and parent_pid via psutil if available."""
    # Fill in parent_pid from psutil when not already set
    if pid > 0 and not proc_node.parent_pid:
        if pid in _ppid_cache:
            proc_node.parent_pid = _ppid_cache[pid]
            # Ensure name cache is populated even on cache-hit path
            if pid not in _name_cache and proc_node.name:
                _name_cache[pid] = proc_node.name
        else:
            try:
                import psutil

                p = psutil.Process(pid)
                ppid = p.ppid()
                if ppid and ppid > 0:
                    proc_node.parent_pid = ppid
                    _ppid_cache[pid] = ppid
                if proc_node.name:
                    _name_cache[pid] = proc_node.name
                # Also fill in cmd_line and exe_path if missing
                if not proc_node.cmd_line:
                    try:
                        cmdline = p.cmdline()
                        if cmdline:
                            proc_node.cmd_line = " ".join(cmdline)
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                if not proc_node.exe_path:
                    with contextlib.suppress(psutil.AccessDenied, psutil.ZombieProcess):
                        proc_node.exe_path = p.exe()
            except Exception:
                _ppid_cache[pid] = 0  # Don't retry for dead processes
                if proc_node.name:
                    _name_cache[pid] = proc_node.name

    # Always populate caches for fast-path chain building, even when parent_pid
    # was already set by the normalizer (e.g. from PsutilCollector ppid field).
    if pid > 0:
        if proc_node.parent_pid and pid not in _ppid_cache:
            _ppid_cache[pid] = proc_node.parent_pid
        if proc_node.name and pid not in _name_cache:
            _name_cache[pid] = proc_node.name

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


def _extract_user_for_process(
    pid: int,
    proc_id: str,
    entities: ExtractedEntities,
    now: datetime,
    event_id: int,
    activity_id: int = 0,
    actor_user=None,
) -> None:
    """Extract UserNode and SPAWNED edge for a process, with psutil fallback."""
    user_name = None
    user_uid = None

    # Tier 1: OCSF actor.user (only on ProcessActivity)
    if actor_user:
        user_name = actor_user.name
        user_uid = actor_user.uid
        # Populate cache for fast-path chain building
        if user_name and pid > 0 and pid not in _username_cache:
            _username_cache[pid] = user_name

    # Tier 2: psutil fallback
    if not user_name and pid > 0:
        if pid in _username_cache:
            user_name = _username_cache[pid] or None
        else:
            try:
                import psutil

                uname = psutil.Process(pid).username()
                if isinstance(uname, str) and uname:
                    user_name = uname
                    _username_cache[pid] = uname
                else:
                    _username_cache[pid] = ""
            except Exception:
                _username_cache[pid] = ""

    if not user_name:
        return

    user_id = user_name
    entities.users.append(UserNode(id=user_id, name=user_name, uid=user_uid, first_seen=now, last_seen=now))
    entities.spawned_edges.append(
        {
            "user_id": user_id,
            "process_id": proc_id,
            "timestamp": now,
            "activity_id": activity_id,
            "event_id": event_id,
        }
    )


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
            entities.risk_indicators.append(
                {
                    "type": "persistence",
                    "persistence_type": persistence.persistence_type,
                    "platform": persistence.platform,
                    "severity": persistence.severity,
                    "mitre_technique": persistence.mitre_technique,
                    "description": persistence.description,
                    "path": persistence.path,
                }
            )

    return entities


def _extract_process_activity(
    event: ProcessActivity,
    event_id: int,
    entities: ExtractedEntities,
    now: datetime,
) -> None:
    proc = event.process
    hostname = event.device.hostname

    start_time = proc.created_time or _resolve_start_time(proc.pid, now)
    proc_id = f"{hostname}:{proc.pid}:{int(start_time.timestamp())}"

    proc_node = ProcessNode(
        id=proc_id,
        name=proc.name,
        pid=proc.pid,
        cmd_line=proc.cmd_line or None,
        exe_path=proc.exe_path or None,
        hostname=hostname,
        start_time=start_time,
        parent_pid=proc.parent_pid,
    )
    _enrich_process_node(proc_node, proc.pid)
    entities.processes.append(proc_node)

    _extract_user_for_process(
        proc.pid,
        proc_id,
        entities,
        now,
        event_id,
        activity_id=event.activity_id,
        actor_user=event.actor.user if event.actor else None,
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
        start_time = proc.created_time or _resolve_start_time(proc.pid, now)
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

        _extract_user_for_process(
            proc.pid,
            proc_id,
            entities,
            now,
            event_id,
            activity_id=event.activity_id,
        )

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
                            entities.risk_indicators.append(
                                {
                                    "type": "connection_context",
                                    "description": f"Localhost IPC: {proc.name} -> {conn_ctx.dest_process} (low risk)",
                                    "severity": "info",
                                    "connection_context": conn_ctx.connection_description,
                                }
                            )
                        else:
                            entities.risk_indicators.append(
                                {
                                    "type": "connection_context",
                                    "description": f"Localhost connection to unknown listener on port {dst_port}",
                                    "severity": "low",
                                    "connection_context": conn_ctx.connection_description,
                                }
                            )
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
        start_time = proc.created_time or _resolve_start_time(proc.pid, now)
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

        _extract_user_for_process(
            proc.pid,
            proc_id,
            entities,
            now,
            event_id,
            activity_id=event.activity_id,
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
        start_time = proc.created_time or _resolve_start_time(proc.pid, now)
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

        _extract_user_for_process(
            proc.pid,
            proc_id,
            entities,
            now,
            event_id,
            activity_id=event.activity_id,
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
        start_time = proc.created_time or _resolve_start_time(proc.pid, now)
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
