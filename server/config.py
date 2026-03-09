"""Fleet server configuration."""

from __future__ import annotations

import os

from pydantic import BaseModel, Field


class ServerSettings(BaseModel):
    """Central fleet server configuration."""

    grpc_port: int = 50051
    http_port: int = 8080

    # Neo4j connection
    neo4j_uri: str = Field(default_factory=lambda: os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    neo4j_user: str = Field(default_factory=lambda: os.environ.get("NEO4J_USER", "neo4j"))
    neo4j_password: str = Field(default_factory=lambda: os.environ.get("NEO4J_PASSWORD", ""))

    # TLS certificates for mTLS
    tls_ca_cert: str = Field(default_factory=lambda: os.environ.get("TLS_CA_CERT", ""))
    tls_server_cert: str = Field(default_factory=lambda: os.environ.get("TLS_SERVER_CERT", ""))
    tls_server_key: str = Field(default_factory=lambda: os.environ.get("TLS_SERVER_KEY", ""))

    # Server tuning
    grpc_max_workers: int = 10
    grpc_max_message_length: int = 16 * 1024 * 1024  # 16 MB

    # JWT authentication
    jwt_secret: str = Field(default_factory=lambda: os.environ.get("JWT_SECRET", ""))
    jwt_ttl_hours: int = 8

    # Bootstrap admin credentials
    bootstrap_admin_user: str = Field(default_factory=lambda: os.environ.get("ADMIN_USER", "admin"))
    bootstrap_admin_password: str = Field(default_factory=lambda: os.environ.get("ADMIN_PASSWORD", ""))

    # Lateral movement detection
    lateral_movement_time_window: int = 300  # seconds

    # NTP clock synchronization
    ntp_server: str = Field(default_factory=lambda: os.environ.get("NTP_SERVER", "pool.ntp.org"))
    ntp_sync_interval: int = 300  # seconds

    # XDR orchestrator
    xdr_poll_interval: int = 15           # orchestrator poll seconds
    xdr_query_timeout: int = 300          # max wait for XDR query completion (seconds)
    incident_auto_close_hours: int = 48   # auto-close stale incidents after this many hours

    # Settings database
    settings_db_path: str = Field(
        default_factory=lambda: os.environ.get("SETTINGS_DB_PATH", "./settings.db")
    )

    # Intel feed aggregator
    intel_refresh_hours: float = Field(
        default_factory=lambda: float(os.environ.get("INTEL_REFRESH_HOURS", "4"))
    )

    # DeepInfra LLM (Diamond Model analysis)
    deepinfra_api_key: str = Field(default_factory=lambda: os.environ.get("DEEPINFRA_API_KEY", ""))
    deepinfra_base_url: str = Field(default_factory=lambda: os.environ.get("DEEPINFRA_BASE_URL", "https://api.deepinfra.com/v1/openai"))
    deepinfra_model: str = Field(default_factory=lambda: os.environ.get("DEEPINFRA_MODEL", "google/gemma-3-27b-it"))
