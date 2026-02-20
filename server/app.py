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
"""

from __future__ import annotations

import logging
import threading
from concurrent import futures

import grpc
import uvicorn

from agent.fleet.proto import fleet_pb2_grpc
from agent.fleet.tls import load_mtls_server_credentials
from server.config import ServerSettings
from server.dashboard import app as dashboard_app
from server.dashboard import set_neo4j
from server.grpc_service import FleetServicer
from server.neo4j_client import Neo4jClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("server")


def main() -> None:
    settings = ServerSettings()

    # Connect to Neo4j
    neo4j_client = Neo4jClient(
        uri=settings.neo4j_uri,
        user=settings.neo4j_user,
        password=settings.neo4j_password,
    )
    neo4j_client.init_schema()

    # Share Neo4j client with dashboard
    set_neo4j(neo4j_client)

    # Build gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=settings.grpc_max_workers),
        options=[
            ("grpc.max_receive_message_length", settings.grpc_max_message_length),
            ("grpc.max_send_message_length", settings.grpc_max_message_length),
        ],
    )
    fleet_pb2_grpc.add_FleetServiceServicer_to_server(FleetServicer(neo4j_client), server)

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
        neo4j_client.close()


if __name__ == "__main__":
    main()
