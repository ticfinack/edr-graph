"""XDR Orchestrator: background worker driving lateral-movement incident lifecycle.

State machine: detected → sweeping → active → closed

- detected: Incident just created by inline detection in SendFindings()
- sweeping: XDR queries enqueued on src/dst agents, waiting for results
- active:   Chains stitched and persisted; follow-on findings accumulate
- closed:   SOC action or auto-close after TTL inactivity
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid

from server.neo4j_client import Neo4jClient, _build_chain_from_xdr_records
from server.settings_db import SettingsDB

logger = logging.getLogger("server.xdr_orchestrator")

_SURV_PULL_INTERVAL = 60  # seconds between surveillance pulls per incident/side


class XdrOrchestrator:
    """Background daemon thread that processes Incident state transitions."""

    def __init__(
        self,
        neo4j: Neo4jClient,
        settings_db: SettingsDB,
        poll_interval: int = 15,
        query_timeout: int = 300,
        auto_close_hours: int = 48,
    ) -> None:
        self._neo4j = neo4j
        self._settings_db = settings_db
        self._poll_interval = poll_interval
        self._query_timeout = query_timeout
        self._auto_close_hours = auto_close_hours
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="xdr-orchestrator",
        )

    def start(self) -> None:
        """Start the background orchestrator thread."""
        self._thread.start()
        logger.info(
            "XDR orchestrator started (poll=%ds, timeout=%ds, auto_close=%dh)",
            self._poll_interval, self._query_timeout, self._auto_close_hours,
        )

    def stop(self) -> None:
        """Stop the background thread."""
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _run(self) -> None:
        while not self._stop.wait(timeout=self._poll_interval):
            try:
                self._process_detected()
            except Exception:
                logger.exception("Error processing detected incidents")
            try:
                self._process_sweeping()
            except Exception:
                logger.exception("Error processing sweeping incidents")
            try:
                self._process_active()
            except Exception:
                logger.exception("Error processing active incidents")

    def _process_detected(self) -> None:
        """detected → sweeping: enqueue XDR queries for each new incident."""
        incidents = self._neo4j.get_incidents_by_status("detected")
        for inc in incidents:
            incident_id = inc["incident_id"]
            dst_agent_id = inc["dst_agent_id"]
            src_agent_id = inc["src_agent_id"]
            pivot_ip = inc["pivot_ip"]

            # Get source host IPs for victim trace
            src_ips = self._neo4j.get_incident_src_ips(incident_id)

            # Extract port from the source finding's IOCs
            finding_id = inc.get("finding_id")
            port = inc.get("dst_port")
            if port is None and finding_id:
                port = self._neo4j.extract_finding_port(finding_id)

            # Enqueue lateral_victim_trace on TARGET agent
            self._settings_db.enqueue_xdr_query(
                str(uuid.uuid4()),
                dst_agent_id,
                f"{incident_id}:victim",
                "lateral_victim_trace",
                json.dumps({"victim_ips": src_ips, "target_port": port}),
            )

            # Enqueue lateral_source_trace on SOURCE agent
            self._settings_db.enqueue_xdr_query(
                str(uuid.uuid4()),
                src_agent_id,
                f"{incident_id}:source",
                "lateral_source_trace",
                json.dumps({"dst_ips": [pivot_ip], "target_port": port}),
            )

            self._neo4j.update_incident_status(incident_id, "sweeping")
            logger.info("Incident %s: detected → sweeping", incident_id)

    def _process_sweeping(self) -> None:
        """sweeping → active: check for completed XDR queries, build chains."""
        incidents = self._neo4j.get_incidents_by_status("sweeping")
        now = time.time()
        for inc in incidents:
            incident_id = inc["incident_id"]
            created_at = inc["created_at"] or 0
            timed_out = (now - created_at) > self._query_timeout

            victim_result = self._settings_db.get_xdr_result(
                f"{incident_id}:victim", "lateral_victim_trace",
            )
            source_result = self._settings_db.get_xdr_result(
                f"{incident_id}:source", "lateral_source_trace",
            )

            victim_done = (
                victim_result is not None and victim_result["status"] == "completed"
            )
            source_done = (
                source_result is not None and source_result["status"] == "completed"
            )

            if (victim_done and source_done) or timed_out:
                source_chain: list[dict] = []
                target_chain: list[dict] = []

                if victim_done:
                    try:
                        data = json.loads(victim_result["result_json"])
                        records = data.get("records", [])
                        if records:
                            target_chain = _build_chain_from_xdr_records(
                                records, reverse=True,
                            )
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass

                if source_done:
                    try:
                        data = json.loads(source_result["result_json"])
                        records = data.get("records", [])
                        if records:
                            source_chain = _build_chain_from_xdr_records(records)
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass

                if source_chain or target_chain:
                    self._neo4j.persist_incident_chains(
                        incident_id, source_chain, target_chain,
                    )

                self._neo4j.update_incident_status(incident_id, "active")
                logger.info(
                    "Incident %s: sweeping → active (src_chain=%d, tgt_chain=%d%s)",
                    incident_id, len(source_chain), len(target_chain),
                    ", timed_out" if timed_out else "",
                )

    def _process_active(self) -> None:
        """active: auto-close if stale; enqueue surveillance pulls every 60s."""
        incidents = self._neo4j.get_incidents_by_status("active")
        now = time.time()
        now_int = int(now)
        ttl_seconds = self._auto_close_hours * 3600
        for inc in incidents:
            incident_id = inc["incident_id"]
            updated_at = inc["updated_at"] or 0

            # 1. Auto-close TTL check
            if (now - updated_at) > ttl_seconds:
                self._neo4j.update_incident_status(incident_id, "closed")
                logger.info("Incident %s: active → closed (auto-close TTL)", incident_id)
                continue

            # 2. Autonomous surveillance pulls
            dst_agent = inc.get("dst_agent_id", "")
            src_agent = inc.get("src_agent_id", "")
            pivot_ip = inc.get("pivot_ip", "")

            # Check if any side needs a pull before fetching shared data
            sides = []
            if dst_agent:
                dst_state = self._settings_db.get_surveillance_pull_state(incident_id, "dst")
                if (now_int - dst_state["last_enqueue_at"]) >= _SURV_PULL_INTERVAL:
                    sides.append(("dst", dst_agent, dst_state))
            if src_agent:
                src_state = self._settings_db.get_surveillance_pull_state(incident_id, "src")
                if (now_int - src_state["last_enqueue_at"]) >= _SURV_PULL_INTERVAL:
                    sides.append(("src", src_agent, src_state))

            if not sides:
                continue

            # Fetch shared data once
            src_ips = self._neo4j.get_incident_src_ips(incident_id)
            src_pids, dst_pids = self._neo4j.get_incident_chain_pids(incident_id)
            src_users, dst_users = self._neo4j.get_incident_chain_usernames(incident_id)

            for side, agent_id, state in sides:
                finding_key = f"{incident_id}:surv_{side}"

                # Skip if there's already a pending query for this side
                if self._settings_db.has_pending_xdr_query(finding_key, "pull_surveillance_logs"):
                    continue

                # Build params based on side
                if side == "dst":
                    ips = src_ips
                    anchor_pids = dst_pids
                    usernames = dst_users
                else:
                    ips = [pivot_ip] if pivot_ip else []
                    anchor_pids = src_pids
                    usernames = src_users

                # Skip if no filter criteria at all
                if not ips and not anchor_pids and not usernames:
                    continue

                params: dict = {"ips": ips, "anchor_pids": anchor_pids, "usernames": usernames, "limit": 200}
                if state["last_record_ts"] > 0:
                    params["since"] = state["last_record_ts"]

                self._settings_db.enqueue_xdr_query(
                    str(uuid.uuid4()), agent_id, finding_key,
                    "pull_surveillance_logs", json.dumps(params),
                )
                self._settings_db.set_surveillance_pull_state(
                    incident_id, side, last_enqueue_at=now_int,
                )
                logger.debug(
                    "Incident %s: enqueued surv pull %s on %s", incident_id, side, agent_id,
                )
