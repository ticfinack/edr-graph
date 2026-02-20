#!/usr/bin/env bash
# Generate self-signed mTLS certificates for demo/testing.
#
# Produces:
#   certs/ca.pem, certs/ca-key.pem           - Certificate Authority
#   certs/server.pem, certs/server-key.pem   - Fleet server certificate
#   certs/agent.pem, certs/agent-key.pem     - Agent client certificate
#
# Usage: ./scripts/generate_certs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_ROOT/certs"

mkdir -p "$CERT_DIR"

echo "=== Generating CA ==="
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
    -keyout "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca.pem" \
    -subj "/CN=EDR Fleet CA/O=edr-graph"

echo "=== Generating Server Certificate ==="
openssl req -newkey rsa:4096 -nodes \
    -keyout "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=fleet-server/O=edr-graph"

openssl x509 -req -sha256 -days 365 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server.pem" \
    -extfile <(printf "subjectAltName=DNS:fleet-server,DNS:localhost,IP:127.0.0.1")

echo "=== Generating Agent Client Certificate ==="
openssl req -newkey rsa:4096 -nodes \
    -keyout "$CERT_DIR/agent-key.pem" \
    -out "$CERT_DIR/agent.csr" \
    -subj "/CN=edr-agent/O=edr-graph"

openssl x509 -req -sha256 -days 365 \
    -in "$CERT_DIR/agent.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/agent.pem"

# Clean up CSR files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl

echo ""
echo "Certificates generated in $CERT_DIR/"
echo "  CA:     ca.pem / ca-key.pem"
echo "  Server: server.pem / server-key.pem"
echo "  Agent:  agent.pem / agent-key.pem"
echo ""
echo "To use with the agent:"
echo "  python -m agent.main --fleet-enabled --fleet-url localhost:50051 \\"
echo "      --config config.yaml"
echo "  (set fleet.ca_cert, fleet.client_cert, fleet.client_key in config.yaml)"
