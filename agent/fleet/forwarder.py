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

import grpc

from agent import metrics
from agent.config import Settings
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

    def __init__(self, settings: Settings, queue: SqliteQueue) -> None:
        self._settings = settings
        self._queue = queue
        self._agent_id = settings.fleet_agent_id or str(uuid.uuid4())
        self._channel: grpc.Channel | None = None
        self._stub: fleet_pb2_grpc.FleetServiceStub | None = None
        self._connected = False

        self._connect()

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

        agent_info = fleet_pb2.AgentInfo(
            agent_id=self._agent_id,
            hostname=platform.node(),
            platform=sys.platform,
            os_version=platform.version(),
            agent_version="0.1.0",
            registered_at=int(time.time()),
        )
        request = fleet_pb2.RegisterAgentRequest(agent_info=agent_info)

        try:
            response = self._stub.RegisterAgent(request, timeout=10)
            if response.accepted:
                self._agent_id = response.agent_id
                self._connected = True
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

    def send_heartbeat(self) -> None:
        """Send heartbeat to fleet server."""
        request = fleet_pb2.HeartbeatRequest(
            agent_id=self._agent_id,
            timestamp=int(time.time()),
            queue_depth=self._queue.count_unprocessed(),
            findings_count=len(self._queue.get_findings(limit=1)),
            status="healthy",
        )
        try:
            self._stub.Heartbeat(request, timeout=10)
            logger.debug("Heartbeat sent")
        except grpc.RpcError as e:
            metrics.fleet_forwarding_errors.labels(error_type="heartbeat").inc()
            logger.debug("Heartbeat failed: %s", e)

    def stop(self) -> None:
        """Close the gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            logger.info("Fleet forwarder stopped")
