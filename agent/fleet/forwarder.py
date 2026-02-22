"""Fleet forwarder: gRPC client with store-and-forward SQLite buffering.

Forwards SecurityFindings and optionally OCSF events to the central
fleet server. Buffers items locally when the network is unavailable
and drains the queue when connectivity is restored.
"""

from __future__ import annotations

import json
import logging
import platform
import time
import uuid
from pathlib import Path

import grpc

from agent import metrics
from agent.config import Settings
from agent.fleet.ip_discovery import PublicIpMonitor, get_local_ips
from agent.fleet.proto import fleet_pb2, fleet_pb2_grpc
from agent.fleet.serializers import finding_to_proto
from agent.fleet.tls import load_mtls_channel_credentials
from agent.queue.sqlite_queue import SqliteQueue
from agent.schema.graph_types import SecurityFinding

logger = logging.getLogger("agent.fleet")


class FleetForwarder:
    """gRPC client that forwards findings/events to the central fleet server.

    Uses a local SQLite forwarding queue for store-and-forward resilience.
    Thread-safe: forward_finding() is called from the analyzer thread,
    while drain_queue() runs in the forwarder thread. SQLite WAL mode
    handles the concurrent access.
    """

    def __init__(self, settings: Settings, queue: SqliteQueue, ntp_monitor=None) -> None:
        self._settings = settings
        self._queue = queue
        self._agent_id = settings.fleet_agent_id or self._load_or_create_agent_id(settings.data_dir)
        self._channel: grpc.Channel | None = None
        self._stub: fleet_pb2_grpc.FleetServiceStub | None = None
        self._connected = False
        self._ntp_monitor = ntp_monitor
        self._public_ip_monitor: PublicIpMonitor | None = None
        if settings.fleet_public_ip_interval > 0:
            self._public_ip_monitor = PublicIpMonitor(
                interval=settings.fleet_public_ip_interval,
            )
            self._public_ip_monitor.start()

        self._connect()

    @staticmethod
    def _load_or_create_agent_id(data_dir: Path) -> str:
        """Load persisted agent_id from disk, or generate and save a new one."""
        id_file = data_dir / "fleet_agent_id"
        try:
            stored = id_file.read_text().strip()
            if stored:
                logger.info("Loaded persisted agent_id: %s", stored)
                return stored
        except FileNotFoundError:
            pass
        new_id = str(uuid.uuid4())
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            id_file.write_text(new_id)
            logger.info("Generated new agent_id: %s", new_id)
        except OSError:
            logger.warning("Could not persist agent_id to %s", id_file)
        return new_id

    def _connect(self) -> None:
        """Establish the gRPC channel (mTLS or insecure for dev)."""
        target = self._settings.fleet_url

        if self._settings.fleet_ca_cert and self._settings.fleet_client_cert and self._settings.fleet_client_key:
            credentials = load_mtls_channel_credentials(
                ca_cert_path=self._settings.fleet_ca_cert,
                client_cert_path=self._settings.fleet_client_cert,
                client_key_path=self._settings.fleet_client_key,
            )
            self._channel = grpc.secure_channel(target, credentials)
            logger.info("Fleet channel (mTLS) → %s", target)
        else:
            self._channel = grpc.insecure_channel(target)
            logger.warning("Fleet channel (insecure) → %s", target)

        self._stub = fleet_pb2_grpc.FleetServiceStub(self._channel)

    def register(self) -> None:
        """Register this agent with the fleet server."""
        import sys

        local_ips = get_local_ips()
        agent_info = fleet_pb2.AgentInfo(
            agent_id=self._agent_id,
            hostname=platform.node(),
            platform=sys.platform,
            os_version=platform.version(),
            agent_version="0.1.0",
            ip_address=local_ips[0] if local_ips else "",
            registered_at=int(time.time()),
            ip_addresses=local_ips,
            public_ip=self._public_ip_monitor.current_ip if self._public_ip_monitor else "",
        )
        request = fleet_pb2.RegisterAgentRequest(
            agent_info=agent_info,
            registration_key=self._settings.fleet_registration_key,
        )

        try:
            response = self._stub.RegisterAgent(request, timeout=10)
            if response.accepted:
                if response.agent_id and response.agent_id != self._agent_id:
                    self._agent_id = response.agent_id
                self._connected = True
                # Persist agent_id so restarts reuse the same identity
                try:
                    id_file = self._settings.data_dir / "fleet_agent_id"
                    id_file.write_text(self._agent_id)
                except OSError:
                    pass
                logger.info("Registered with fleet server (agent_id=%s)", self._agent_id)
            else:
                logger.warning("Fleet registration rejected: %s", response.message)
        except grpc.RpcError as e:
            logger.warning("Fleet registration failed: %s", e)
            # Agent will retry on next drain cycle

    def forward_finding(self, finding: SecurityFinding) -> None:
        """Queue a finding for forwarding. Called from analyzer_thread."""
        payload = finding.model_dump_json()
        self._queue.push_forwarding("finding", payload)

    def forward_events(self, events_json: list[str]) -> None:
        """Queue OCSF events for forwarding. Called from processor_thread."""
        for event_json in events_json:
            self._queue.push_forwarding("event", event_json)

    def drain_queue(self) -> None:
        """Attempt to send all buffered items. Called by forwarder_thread."""
        batch = self._queue.pop_forwarding_batch(batch_size=50)
        if not batch:
            return

        # Separate findings and events
        finding_items = [(id_, payload) for id_, typ, payload in batch if typ == "finding"]
        event_items = [(id_, payload) for id_, typ, payload in batch if typ == "event"]

        # Send findings
        if finding_items:
            self._send_findings_batch(finding_items)

        # Send events
        if event_items:
            self._send_events_batch(event_items)

        # Update queue depth metric
        metrics.fleet_forwarding_queue_depth.set(self._queue.forwarding_queue_depth())

    def _send_findings_batch(self, items: list[tuple[int, str]]) -> None:
        """Send a batch of findings via gRPC."""
        ids = [id_ for id_, _ in items]
        protos = []
        for _, payload in items:
            finding = SecurityFinding.model_validate_json(payload)
            protos.append(finding_to_proto(finding))

        request = fleet_pb2.SendFindingsRequest(
            agent_id=self._agent_id,
            findings=protos,
        )

        start = time.monotonic()
        try:
            response = self._stub.SendFindings(request, timeout=30)
            elapsed = time.monotonic() - start
            metrics.fleet_forwarding_latency.observe(elapsed)
            metrics.fleet_items_forwarded.labels(item_type="finding").inc(response.accepted_count)
            self._queue.mark_forwarded(ids)
            logger.debug("Forwarded %d findings (%.2fs)", response.accepted_count, elapsed)
        except grpc.RpcError as e:
            metrics.fleet_forwarding_errors.labels(error_type="grpc").inc()
            self._queue.mark_forward_failed(ids, max_retries=self._settings.fleet_retry_max)
            logger.warning("Failed to forward findings: %s", e)

    def _send_events_batch(self, items: list[tuple[int, str]]) -> None:
        """Send a batch of OCSF events via gRPC."""
        ids = [id_ for id_, _ in items]
        protos = []
        for _, payload in items:
            event_data = json.loads(payload)
            class_uid = event_data.get("class_uid", 0)
            protos.append(fleet_pb2.OcsfEvent(class_uid=class_uid, event_json=payload))

        request = fleet_pb2.SendEventsRequest(
            agent_id=self._agent_id,
            events=protos,
        )

        start = time.monotonic()
        try:
            response = self._stub.SendEvents(request, timeout=30)
            elapsed = time.monotonic() - start
            metrics.fleet_forwarding_latency.observe(elapsed)
            metrics.fleet_items_forwarded.labels(item_type="event").inc(response.accepted_count)
            self._queue.mark_forwarded(ids)
            logger.debug("Forwarded %d events (%.2fs)", response.accepted_count, elapsed)
        except grpc.RpcError as e:
            metrics.fleet_forwarding_errors.labels(error_type="grpc").inc()
            self._queue.mark_forward_failed(ids, max_retries=self._settings.fleet_retry_max)
            logger.warning("Failed to forward events: %s", e)

    def set_enforcement_stages(
        self,
        allowlist=None,
        blocklist=None,
        fast_blocklist=None,
        allowlist_cache=None,
    ):
        """Wire enforcement stages so network rules can be hot-reloaded."""
        self._allowlist = allowlist
        self._blocklist = blocklist
        self._fast_blocklist = fast_blocklist
        self._allowlist_cache = allowlist_cache

    def _apply_rules(self, rules: list[dict]) -> None:
        """Split rules by action+stage and push to the appropriate enforcement stages."""
        allow_pre_graph = []
        allow_response = []
        block_fast_path = []
        block_response = []

        for r in rules:
            action = r.get("action", "")
            stage = r.get("stage", "")
            if action == "allow" and stage == "pre_graph":
                allow_pre_graph.append(r)
            elif action == "allow" and stage == "response":
                allow_response.append(r)
            elif action == "block" and stage == "fast_path":
                block_fast_path.append(r)
            elif action == "block" and stage == "response":
                block_response.append(r)

        if getattr(self, "_allowlist", None):
            self._allowlist.set_network_rules(allow_pre_graph + allow_response)
        if getattr(self, "_allowlist_cache", None):
            self._allowlist_cache.invalidate()
        if getattr(self, "_blocklist", None):
            self._blocklist.set_network_rules(block_fast_path + block_response)
        if getattr(self, "_fast_blocklist", None):
            self._fast_blocklist.set_network_rules(block_fast_path)

    # Whitelist of agent settings that can be overridden via heartbeat config push
    _CONFIG_WHITELIST = {
        "response_mode": str,
        "analyzer_interval": float,
        "collector_poll_interval": float,
        "novel_edge_threshold": int,
        "dga_score_threshold": float,
        "graph_ttl_hours": int,
        "auto_respond": bool,
        "auto_terminate": bool,
        "fleet_forward_events": bool,
        "ioc_feeds_enabled": bool,
    }

    def _verify_config_signature(self, config_json: str, signature: str) -> bool:
        """Verify HMAC-SHA256 signature of config_json using a per-agent derived key."""
        import hashlib
        import hmac as hmac_mod

        reg_key = self._settings.fleet_registration_key
        if not reg_key:
            return False
        signing_key = hmac_mod.new(
            reg_key.encode(), self._agent_id.encode(), hashlib.sha256
        ).digest()
        expected = hmac_mod.new(
            signing_key, config_json.encode(), hashlib.sha256
        ).hexdigest()
        return hmac_mod.compare_digest(expected, signature)

    def _apply_config_overrides(self, config_json: str, signature: str = "") -> None:
        """Parse JSON config from heartbeat response and apply whitelisted overrides.

        Config is only applied if the HMAC-SHA256 signature is valid, preventing
        attackers from injecting configuration via rogue servers or MITM.
        """
        if not config_json:
            return
        if not signature or not self._verify_config_signature(config_json, signature):
            logger.warning("Rejected config push: invalid or missing HMAC signature")
            return
        try:
            overrides = json.loads(config_json)
        except (json.JSONDecodeError, TypeError):
            logger.debug("Bad config_json from heartbeat: %s", config_json[:100])
            return

        # Extract and distribute rules before processing scalar overrides
        rules = overrides.pop("rules", [])
        if isinstance(rules, list):
            self._apply_rules(rules)

        for key, converter in self._CONFIG_WHITELIST.items():
            if key not in overrides:
                continue
            raw = overrides[key]
            try:
                value = str(raw).lower() in ("true", "1", "yes") if converter is bool else converter(raw)
                if hasattr(self._settings, key):
                    setattr(self._settings, key, value)
            except (ValueError, TypeError):
                logger.debug("Cannot convert config override %s=%r", key, raw)

    def send_heartbeat(self) -> None:
        """Send heartbeat to fleet server, including NTP clock offset and IPs."""
        clock_offset_ms = 0
        if self._ntp_monitor is not None:
            clock_offset_ms = self._ntp_monitor.current_offset_ms

        local_ips = get_local_ips()
        request = fleet_pb2.HeartbeatRequest(
            agent_id=self._agent_id,
            timestamp=int(time.time()),
            queue_depth=self._queue.count_unprocessed(),
            findings_count=len(self._queue.get_findings(limit=1)),
            status="healthy",
            clock_offset_ms=clock_offset_ms,
            ip_addresses=local_ips,
            public_ip=self._public_ip_monitor.current_ip if self._public_ip_monitor else "",
        )
        try:
            response = self._stub.Heartbeat(request, timeout=10)
            if response.config_json:
                self._apply_config_overrides(response.config_json, response.config_signature)
            logger.debug("Heartbeat sent")
        except grpc.RpcError as e:
            metrics.fleet_forwarding_errors.labels(error_type="heartbeat").inc()
            logger.debug("Heartbeat failed: %s", e)

    def stop(self) -> None:
        """Close the gRPC channel and stop background monitors."""
        if self._public_ip_monitor:
            self._public_ip_monitor.stop()
        if self._channel:
            self._channel.close()
            self._channel = None
            logger.info("Fleet forwarder stopped")
