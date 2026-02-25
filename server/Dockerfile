FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for grpcio compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt
RUN pip install --no-cache-dir grpcio-tools>=1.60.0

# Copy proto definitions and generate stubs
COPY proto/ /app/proto/
COPY agent/fleet/__init__.py /app/agent/fleet/__init__.py
COPY agent/fleet/proto/__init__.py /app/agent/fleet/proto/__init__.py
COPY agent/fleet/serializers.py /app/agent/fleet/serializers.py
COPY agent/fleet/tls.py /app/agent/fleet/tls.py
COPY agent/schema/graph_types.py /app/agent/schema/graph_types.py
COPY agent/__init__.py /app/agent/__init__.py
COPY agent/schema/__init__.py /app/agent/schema/__init__.py
COPY agent/intel/ /app/agent/intel/

RUN python -m grpc_tools.protoc \
    --proto_path=proto \
    --python_out=agent/fleet/proto \
    --grpc_python_out=agent/fleet/proto \
    --pyi_out=agent/fleet/proto \
    proto/fleet.proto \
    && sed -i 's/^import fleet_pb2/from agent.fleet.proto import fleet_pb2/' \
       agent/fleet/proto/fleet_pb2_grpc.py

# Copy server code and global rules
COPY server/ /app/server/
COPY rules/ /app/rules/

EXPOSE 50051 8080

CMD ["python", "-m", "server.app"]
