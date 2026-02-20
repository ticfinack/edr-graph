#!/usr/bin/env bash
# Generate Python gRPC stubs from proto definitions.
# Usage: ./scripts/generate_proto.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$PROJECT_ROOT/proto"
OUT_DIR="$PROJECT_ROOT/agent/fleet/proto"

mkdir -p "$OUT_DIR"

python -m grpc_tools.protoc \
    --proto_path="$PROTO_DIR" \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    --pyi_out="$OUT_DIR" \
    "$PROTO_DIR/fleet.proto"

# Fix relative imports in generated code (grpc_tools generates broken imports)
if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' 's/^import fleet_pb2/from agent.fleet.proto import fleet_pb2/' "$OUT_DIR/fleet_pb2_grpc.py"
else
    sed -i 's/^import fleet_pb2/from agent.fleet.proto import fleet_pb2/' "$OUT_DIR/fleet_pb2_grpc.py"
fi

echo "Proto stubs generated in $OUT_DIR"
