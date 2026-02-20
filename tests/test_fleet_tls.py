"""Tests for fleet TLS credential loading."""

import pytest

from agent.fleet.tls import load_mtls_channel_credentials


class TestLoadMtlsCredentials:
    def test_missing_ca_cert_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="CA certificate"):
            load_mtls_channel_credentials(
                ca_cert_path=str(tmp_path / "nonexistent.pem"),
                client_cert_path=str(tmp_path / "client.pem"),
                client_key_path=str(tmp_path / "client-key.pem"),
            )

    def test_missing_client_cert_raises(self, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("dummy-ca")
        with pytest.raises(FileNotFoundError, match="client certificate"):
            load_mtls_channel_credentials(
                ca_cert_path=str(ca),
                client_cert_path=str(tmp_path / "nonexistent.pem"),
                client_key_path=str(tmp_path / "client-key.pem"),
            )

    def test_missing_client_key_raises(self, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("dummy-ca")
        cert = tmp_path / "client.pem"
        cert.write_text("dummy-cert")
        with pytest.raises(FileNotFoundError, match="client key"):
            load_mtls_channel_credentials(
                ca_cert_path=str(ca),
                client_cert_path=str(cert),
                client_key_path=str(tmp_path / "nonexistent.pem"),
            )

    def test_valid_files_returns_credentials(self, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n")
        cert = tmp_path / "client.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIBclient\n-----END CERTIFICATE-----\n")
        key = tmp_path / "client-key.pem"
        key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----\n")

        creds = load_mtls_channel_credentials(
            ca_cert_path=str(ca),
            client_cert_path=str(cert),
            client_key_path=str(key),
        )
        # grpc.ssl_channel_credentials returns a ChannelCredentials object
        assert creds is not None
