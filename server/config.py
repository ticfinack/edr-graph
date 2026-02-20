"""Fleet server configuration."""

from __future__ import annotations

import os

from pydantic import BaseModel, Field


class ServerSettings(BaseModel):
    """Central fleet server configuration."""

    grpc_port: int = 50051
    http_port: int = 8080

    # Neo4j connection
    neo4j_uri: str = Field(
        default_factory=lambda: os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    )
    neo4j_user: str = Field(
        default_factory=lambda: os.environ.get("NEO4J_USER", "neo4j")
    )
    neo4j_password: str = Field(
        default_factory=lambda: os.environ.get("NEO4J_PASSWORD", "changeme")
    )

    # TLS certificates for mTLS
    tls_ca_cert: str = Field(
        default_factory=lambda: os.environ.get("TLS_CA_CERT", "")
    )
    tls_server_cert: str = Field(
        default_factory=lambda: os.environ.get("TLS_SERVER_CERT", "")
    )
    tls_server_key: str = Field(
        default_factory=lambda: os.environ.get("TLS_SERVER_KEY", "")
    )

    # Server tuning
    grpc_max_workers: int = 10
    grpc_max_message_length: int = 16 * 1024 * 1024  # 16 MB
