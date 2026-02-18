#!/usr/bin/env bash
# EDR Graph Agent — Linux Installation Script
#
# Usage:
#   sudo bash deploy/install.sh
#
# This script:
#   1. Creates the edr-graph service user
#   2. Installs Python dependencies
#   3. Copies agent files to /opt/edr-graph
#   4. Writes initial config to /etc/edr-graph/config.yaml
#   5. Installs and enables the systemd service
#   6. Creates required directories
#   7. Starts the agent and verifies it's running

set -euo pipefail

# --- Configuration ---
INSTALL_DIR="/opt/edr-graph"
CONFIG_DIR="/etc/edr-graph"
DATA_DIR="/var/lib/edr-graph"
QUARANTINE_DIR="/var/edr-graph/quarantine"
LOG_DIR="/var/log/edr-graph"
HEARTBEAT_DIR="/tmp/edr-heartbeats"
SERVICE_USER="edr-graph"
SERVICE_GROUP="edr-graph"
SYSTEMD_UNIT="/etc/systemd/system/edr-graph.service"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Pre-flight checks ---
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    log_error "Python 3 is required but not found"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ]]; then
    log_error "Python 3.11+ is required (found $PYTHON_VERSION)"
    exit 1
fi
log_info "Python $PYTHON_VERSION found"

# --- Step 1: Create service user ---
if id "$SERVICE_USER" &>/dev/null; then
    log_info "User '$SERVICE_USER' already exists"
else
    log_info "Creating service user '$SERVICE_USER'"
    useradd \
        --system \
        --no-create-home \
        --home-dir "$INSTALL_DIR" \
        --shell /usr/sbin/nologin \
        --comment "EDR Graph Agent" \
        "$SERVICE_USER"
fi

# --- Step 2: Create directories ---
log_info "Creating directories"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$QUARANTINE_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$HEARTBEAT_DIR"

# --- Step 3: Copy agent files ---
log_info "Copying agent files to $INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Copy Python package and config
cp -r "$SCRIPT_DIR/agent" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/pyproject.toml" "$INSTALL_DIR/"
if [[ -f "$SCRIPT_DIR/config.yaml" ]]; then
    cp "$SCRIPT_DIR/config.yaml" "$INSTALL_DIR/"
fi

# --- Step 4: Install Python dependencies ---
log_info "Installing Python dependencies"
cd "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -e .

# --- Step 5: Write config ---
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    log_info "Writing initial config to $CONFIG_DIR/config.yaml"
    cat > "$CONFIG_DIR/config.yaml" << 'YAML'
# EDR Graph Agent Configuration
# See config.yaml in the source repository for all options.

agent:
  log_level: "INFO"
  log_format: "json"
  data_dir: "/var/lib/edr-graph"

collector:
  poll_interval: 5.0

response:
  auto_respond: false
  auto_terminate: false

persistence:
  watchdog_enabled: true
  heartbeat_interval_seconds: 10
  tamper_check_interval_seconds: 60

metrics:
  enabled: true
  port: 9100
YAML
else
    log_warn "Config already exists at $CONFIG_DIR/config.yaml — not overwriting"
fi

# --- Step 6: Set permissions ---
log_info "Setting permissions"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$QUARANTINE_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$HEARTBEAT_DIR"
chmod 750 "$INSTALL_DIR"
chmod 700 "$DATA_DIR"
chmod 700 "$QUARANTINE_DIR"

# Config readable by service user only
chown root:"$SERVICE_GROUP" "$CONFIG_DIR/config.yaml"
chmod 640 "$CONFIG_DIR/config.yaml"

# --- Step 7: Install systemd service ---
log_info "Installing systemd service"
cp "$SCRIPT_DIR/deploy/edr-graph.service" "$SYSTEMD_UNIT"

# Update ExecStart to use the venv
sed -i "s|ExecStart=.*|ExecStart=$INSTALL_DIR/.venv/bin/edr-graph --no-dashboard --log-format json --config $CONFIG_DIR/config.yaml|" "$SYSTEMD_UNIT"

# Update environment variables
sed -i "s|Environment=EDR_DATA_DIR=.*|Environment=EDR_DATA_DIR=$DATA_DIR|" "$SYSTEMD_UNIT"
sed -i "s|Environment=EDR_QUARANTINE_DIR=.*|Environment=EDR_QUARANTINE_DIR=$QUARANTINE_DIR|" "$SYSTEMD_UNIT"

systemctl daemon-reload
systemctl enable edr-graph.service
log_info "Service installed and enabled"

# --- Step 8: Start the agent ---
log_info "Starting edr-graph service"
systemctl start edr-graph.service

# Wait a moment for startup
sleep 2

# --- Step 9: Verify ---
if systemctl is-active --quiet edr-graph.service; then
    log_info "edr-graph is running"
    systemctl status edr-graph.service --no-pager
else
    log_error "edr-graph failed to start"
    journalctl -u edr-graph.service --no-pager -n 20
    exit 1
fi

echo ""
log_info "Installation complete!"
log_info "  Config:     $CONFIG_DIR/config.yaml"
log_info "  Data:       $DATA_DIR"
log_info "  Quarantine: $QUARANTINE_DIR"
log_info "  Logs:       journalctl -u edr-graph -f"
log_info "  Health:     curl http://127.0.0.1:9100/health"
log_info "  Metrics:    curl http://127.0.0.1:9100/metrics"
