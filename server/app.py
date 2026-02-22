"""Fleet server entry point: starts gRPC service + HTTP dashboard.

Usage:
    python -m server.app

Environment variables:
    NEO4J_URI       - Neo4j connection URI (default: bolt://localhost:7687)
    NEO4J_USER      - Neo4j username (default: neo4j)
    NEO4J_PASSWORD  - Neo4j password (default: changeme)
    TLS_CA_CERT     - CA certificate path for mTLS (optional)
    TLS_SERVER_CERT - Server certificate path for mTLS (optional)
    TLS_SERVER_KEY  - Server private key path for mTLS (optional)
    JWT_SECRET      - Secret key for JWT signing (auto-generated if not set)
    ADMIN_USER      - Bootstrap admin username (default: admin)
    ADMIN_PASSWORD  - Bootstrap admin password (auto-generated if not set)
    NTP_SERVER      - NTP server for clock sync (default: pool.ntp.org)
    SETTINGS_DB_PATH - Path to settings SQLite database (default: ./settings.db)
"""

from __future__ import annotations

import logging
import secrets
import string
import threading
from concurrent import futures
from pathlib import Path

import grpc
import uvicorn

from agent.fleet.proto import fleet_pb2_grpc
from agent.fleet.tls import load_mtls_server_credentials
from server.auth import hash_password, set_jwt_secret
from server.config import ServerSettings
from server.dashboard import app as dashboard_app
from server.dashboard import set_neo4j, set_settings, set_settings_db
from server.grpc_service import FleetServicer
from server.neo4j_client import Neo4jClient
from server.ntp_sync import NtpMonitor
from server.settings_db import SettingsDB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("server")


def _generate_password(length: int = 24) -> str:
    """Generate a random password for bootstrap."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _migrate_neo4j_to_sqlite(neo4j_client: Neo4jClient, settings_db: SettingsDB) -> None:
    """One-time migration: copy users and registration keys from Neo4j to SQLite."""
    if not settings_db.is_empty():
        return

    try:
        users = neo4j_client.get_all_dashboard_users()
        keys = neo4j_client.get_all_registration_keys()
    except Exception:
        logger.debug("Neo4j migration query failed (may not have data)", exc_info=True)
        return

    if not users and not keys:
        return

    migrated_users = 0
    for u in users:
        try:
            settings_db.create_user(u["username"], u["password_hash"], role=u.get("role", "admin"))
            migrated_users += 1
        except Exception:
            logger.debug("Failed to migrate user %s", u.get("username"), exc_info=True)

    migrated_keys = 0
    for k in keys:
        try:
            conn = settings_db._conn()
            conn.execute(
                "INSERT OR IGNORE INTO registration_keys "
                "(key, label, created_at, created_by, expires_at, max_uses, use_count, revoked, revoked_at, revoked_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    k["key"],
                    k.get("label", ""),
                    k.get("created_at", 0),
                    k.get("created_by", ""),
                    k.get("expires_at"),
                    k.get("max_uses"),
                    k.get("use_count", 0),
                    1 if k.get("revoked") else 0,
                    k.get("revoked_at"),
                    k.get("revoked_by"),
                ),
            )
            conn.commit()
            migrated_keys += 1
        except Exception:
            logger.debug("Failed to migrate key %s", k.get("key", "")[:8], exc_info=True)

    logger.info("Migrated %d users and %d registration keys from Neo4j to SQLite", migrated_users, migrated_keys)


def main() -> None:
    settings = ServerSettings()

    # ── JWT secret ──
    if not settings.jwt_secret:
        settings.jwt_secret = secrets.token_hex(32)
        logger.warning("JWT_SECRET not set -- generated ephemeral secret (tokens won't survive restart)")
    set_jwt_secret(settings.jwt_secret)

    # ── NTP monitor ──
    ntp_monitor = NtpMonitor(ntp_server=settings.ntp_server, interval=settings.ntp_sync_interval)
    ntp_monitor.start()
    logger.info("NTP monitor started (server=%s, interval=%ds)", settings.ntp_server, settings.ntp_sync_interval)

    # ── Settings database (SQLite) ──
    global_rules_path = Path(__file__).parent.parent / "rules" / "defaults" / "stage2_blocklist.yml"
    settings_db = SettingsDB(settings.settings_db_path, global_rules_path=global_rules_path)

    # ── Connect to Neo4j ──
    neo4j_client = Neo4jClient(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    neo4j_client.init_schema()

    # ── Migrate Neo4j users/keys to SQLite (one-time) ──
    _migrate_neo4j_to_sqlite(neo4j_client, settings_db)

    # ── Bootstrap admin user ──
    if settings_db.count_users() == 0:
        admin_user = settings.bootstrap_admin_user
        admin_pass = settings.bootstrap_admin_password
        if not admin_pass:
            admin_pass = _generate_password()
            logger.warning("ADMIN_PASSWORD not set -- generated bootstrap password: %s", admin_pass)
        settings_db.create_user(admin_user, hash_password(admin_pass), role="admin")
        logger.info("Bootstrap admin user created: %s", admin_user)

    # ── Share state with dashboard ──
    set_neo4j(neo4j_client)
    set_settings(settings)
    set_settings_db(settings_db)

    # ── Mount static files for SPA ──
    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        from fastapi.responses import HTMLResponse
        from fastapi.staticfiles import StaticFiles

        dashboard_app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @dashboard_app.get("/", response_class=HTMLResponse)
        async def serve_spa():
            index = static_dir / "index.html"
            return index.read_text()

    # ── Build gRPC server ──
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=settings.grpc_max_workers),
        options=[
            ("grpc.max_receive_message_length", settings.grpc_max_message_length),
            ("grpc.max_send_message_length", settings.grpc_max_message_length),
        ],
    )
    fleet_pb2_grpc.add_FleetServiceServicer_to_server(
        FleetServicer(neo4j_client, settings_db=settings_db), server
    )

    # Configure TLS
    if settings.tls_ca_cert and settings.tls_server_cert and settings.tls_server_key:
        credentials = load_mtls_server_credentials(
            ca_cert_path=settings.tls_ca_cert,
            server_cert_path=settings.tls_server_cert,
            server_key_path=settings.tls_server_key,
        )
        server.add_secure_port(f"[::]:{settings.grpc_port}", credentials)
        logger.info("gRPC server (mTLS) on port %d", settings.grpc_port)
    else:
        server.add_insecure_port(f"[::]:{settings.grpc_port}")
        logger.warning("gRPC server (insecure) on port %d", settings.grpc_port)

    server.start()
    logger.info("gRPC server started")

    # Start HTTP dashboard in a thread
    dashboard_thread = threading.Thread(
        target=uvicorn.run,
        args=(dashboard_app,),
        kwargs={"host": "0.0.0.0", "port": settings.http_port, "log_level": "info"},
        daemon=True,
        name="dashboard",
    )
    dashboard_thread.start()
    logger.info("Fleet dashboard on http://0.0.0.0:%d", settings.http_port)

    # Block until terminated
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop(grace=5)
        ntp_monitor.stop()
        settings_db.close()
        neo4j_client.close()


if __name__ == "__main__":
    main()
