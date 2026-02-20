"""Mutual TLS credential loading for fleet gRPC connections."""

from __future__ import annotations

import logging
from pathlib import Path

import grpc

logger = logging.getLogger("agent.fleet")


def load_mtls_channel_credentials(
    ca_cert_path: str,
    client_cert_path: str,
    client_key_path: str,
) -> grpc.ChannelCredentials:
    """Load mutual TLS credentials for the agent gRPC channel.

    Args:
        ca_cert_path: Path to the CA certificate (PEM).
        client_cert_path: Path to the client certificate (PEM).
        client_key_path: Path to the client private key (PEM).

    Returns:
        gRPC channel credentials configured for mTLS.

    Raises:
        FileNotFoundError: If any certificate file is missing.
    """
    for path, label in [
        (ca_cert_path, "CA certificate"),
        (client_cert_path, "client certificate"),
        (client_key_path, "client key"),
    ]:
        if not Path(path).is_file():
            raise FileNotFoundError(f"{label} not found: {path}")

    ca_cert = Path(ca_cert_path).read_bytes()
    client_cert = Path(client_cert_path).read_bytes()
    client_key = Path(client_key_path).read_bytes()

    return grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert,
    )


def load_mtls_server_credentials(
    ca_cert_path: str,
    server_cert_path: str,
    server_key_path: str,
) -> grpc.ServerCredentials:
    """Load mutual TLS credentials for the fleet gRPC server.

    Args:
        ca_cert_path: Path to the CA certificate (PEM).
        server_cert_path: Path to the server certificate (PEM).
        server_key_path: Path to the server private key (PEM).

    Returns:
        gRPC server credentials configured for mTLS.
    """
    ca_cert = Path(ca_cert_path).read_bytes()
    server_cert = Path(server_cert_path).read_bytes()
    server_key = Path(server_key_path).read_bytes()

    return grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(server_key, server_cert)],
        root_certificates=ca_cert,
        require_client_auth=True,
    )
