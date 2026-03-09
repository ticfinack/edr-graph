#!/usr/bin/env bash
# EDR Graph Agent — macOS Installation Script
#
# Usage:
#   sudo bash deploy/install_macos.sh [OPTIONS]
#
# Options:
#   --fleet-url URL           Fleet server gRPC address (default: 10.199.0.5:50051)
#   --registration-key KEY    Fleet registration key
#   --api-key KEY             DeepInfra API key (baked into launchd plist)
#   --upgrade                 Update code+venv, preserve config
#   --no-start                Install without starting the daemon
#
# This script:
#   1. Verifies macOS and root
#   2. Finds a suitable Python 3.11+
#   3. Copies agent files to /opt/edr-graph
#   4. Creates venv and installs the package
#   5. Writes production config to /etc/edr-graph/config.yaml
#   6. Installs log rotation via newsyslog
#   7. Installs and starts the launchd daemon

set -euo pipefail

# --- Configuration ---
INSTALL_DIR="/opt/edr-graph"
CONFIG_DIR="/etc/edr-graph"
DATA_DIR="/var/lib/edr-graph"
QUARANTINE_DIR="/var/edr-graph/quarantine"
LOG_DIR="/var/log/edr-graph"
HEARTBEAT_DIR="/tmp/edr-heartbeats"
PLIST_NAME="com.edgeaspect.edr-graph"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}.plist"
NEWSYSLOG_CONF="/etc/newsyslog.d/edr-graph.conf"

# Defaults
FLEET_URL="10.199.0.5:50051"
REGISTRATION_KEY=""
API_KEY=""
UPGRADE=false
NO_START=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Parse CLI arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --fleet-url)
            FLEET_URL="$2"; shift 2 ;;
        --registration-key)
            REGISTRATION_KEY="$2"; shift 2 ;;
        --api-key)
            API_KEY="$2"; shift 2 ;;
        --upgrade)
            UPGRADE=true; shift ;;
        --no-start)
            NO_START=true; shift ;;
        -h|--help)
            head -n 14 "$0" | tail -n 13
            exit 0 ;;
        *)
            log_error "Unknown option: $1"
            exit 1 ;;
    esac
done

# --- Pre-flight checks ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    log_error "This installer is for macOS only (detected: $(uname -s))"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# Find Python 3.11+ — check absolute paths to avoid PATH issues under sudo
# Prefer 3.11-3.13 over 3.14+ (kuzu lacks pre-built wheels for 3.14)
PYTHON_BIN=""
PYTHON_CANDIDATES=(
    # uv-managed (root) — sorted newest-first within 3.11-3.13 range
    /var/root/.local/share/uv/python/cpython-3.13*/bin/python3
    /var/root/.local/share/uv/python/cpython-3.12*/bin/python3
    /var/root/.local/share/uv/python/cpython-3.11*/bin/python3
    # Homebrew versioned
    /opt/homebrew/bin/python3.13
    /opt/homebrew/bin/python3.12
    /opt/homebrew/bin/python3.11
    /usr/local/bin/python3.13
    /usr/local/bin/python3.12
    /usr/local/bin/python3.11
    # Homebrew/system unversioned (may be 3.14+, used as fallback)
    /opt/homebrew/bin/python3
    /usr/local/bin/python3
    /usr/bin/python3
)

for candidate in "${PYTHON_CANDIDATES[@]}"; do
    if [[ -x "$candidate" ]]; then
        py_version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
        if [[ -n "$py_version" ]]; then
            py_major=$(echo "$py_version" | cut -d. -f1)
            py_minor=$(echo "$py_version" | cut -d. -f2)
            if [[ "$py_major" -ge 3 && "$py_minor" -ge 11 ]]; then
                PYTHON_BIN="$candidate"
                break
            fi
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    log_error "Python 3.11+ is required but not found"
    log_error "Checked: uv-managed, /opt/homebrew/bin, /usr/local/bin, /usr/bin"
    log_error "Install Python via: brew install python@3.13"
    exit 1
fi

PYTHON_VERSION=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log_info "Python $PYTHON_VERSION found at $PYTHON_BIN"

# --- Locate source directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    log_error "Cannot find project root (expected pyproject.toml in $SCRIPT_DIR)"
    exit 1
fi
log_info "Source directory: $SCRIPT_DIR"

# --- Step 1: Stop existing daemon (upgrade) ---
if [[ "$UPGRADE" == true ]] || launchctl print "system/${PLIST_NAME}" &>/dev/null; then
    log_info "Stopping existing daemon"
    launchctl bootout "system/${PLIST_NAME}" 2>/dev/null || \
        launchctl unload -w "$PLIST_DEST" 2>/dev/null || true
    # Wait for launchd to fully deregister before re-bootstrapping
    for _i in $(seq 1 10); do
        launchctl print "system/${PLIST_NAME}" &>/dev/null || break
        sleep 1
    done
fi

# --- Step 2: Create directories ---
log_info "Creating directories"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$QUARANTINE_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$HEARTBEAT_DIR"

# --- Step 3: Copy source ---
log_info "Copying agent files to $INSTALL_DIR"
rsync -a --delete \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.git' \
    --exclude='.venv' \
    --exclude='edr_data' \
    --exclude='config.local.yaml' \
    --exclude='.env' \
    --exclude='.claude' \
    --exclude='test-results' \
    --exclude='.ruff_cache' \
    --exclude='.pytest_cache' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"

# --- Step 4: Create venv + install package ---
if [[ "$UPGRADE" == true && -d "$INSTALL_DIR/.venv" ]]; then
    log_info "Upgrading package (preserving existing venv)"
    "$INSTALL_DIR/.venv/bin/pip" install --quiet --force-reinstall --no-deps .
    # Also update deps in case pyproject.toml changed
    "$INSTALL_DIR/.venv/bin/pip" install --quiet .
else
    log_info "Creating virtual environment"
    "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
    log_info "Installing package and dependencies"
    "$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
    "$INSTALL_DIR/.venv/bin/pip" install --quiet .
fi

# Verify installation
if ! "$INSTALL_DIR/.venv/bin/python3" -c "import agent.main" 2>/dev/null; then
    log_error "Package installation failed — 'agent.main' not importable"
    exit 1
fi
log_info "Package installed successfully"

# --- Step 5: Write config ---
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    log_info "Writing production config to $CONFIG_DIR/config.yaml"
    cat > "$CONFIG_DIR/config.yaml" << YAML
# EDR Graph Agent — macOS Production Configuration
# Generated by install_macos.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

agent:
  name: "edr-graph-agent"
  log_level: "INFO"
  log_format: "json"
  data_dir: "/var/lib/edr-graph"

collector:
  poll_interval: 10.0
  buffer_size: 500
  event_retention_hours: 24

analysis:
  llm:
    model: "google/gemma-3-27b-it"
    api_key_env: "DEEPINFRA_API_KEY"
  dga:
    entropy_threshold: 3.5
    score_threshold: 0.6
    allowlist:
      - "googleapis.com"
      - "cloudflare.com"
      - "amazonaws.com"
      - "windows.net"
      - "office365.com"
      - "microsoftonline.com"

response:
  auto_respond: false
  auto_terminate: false
  quarantine_dir: "/var/edr-graph/quarantine"

persistence:
  watchdog_enabled: true
  heartbeat_interval_seconds: 10
  tamper_check_interval_seconds: 60

metrics:
  enabled: true
  port: 9100

dashboard:
  port: 9200
  refresh_interval: 5.0
  auto_open_browser: false

graph:
  max_memory_mb: 512
  ttl_hours: 24

fleet:
  enabled: true
  url: "${FLEET_URL}"
  registration_key: "${REGISTRATION_KEY}"
  forward_interval: 10
  forward_events: false
  heartbeat_interval: 30
  flight_recorder_ttl_hours: 6
YAML
else
    log_warn "Config already exists at $CONFIG_DIR/config.yaml — not overwriting"
    if [[ "$UPGRADE" == true ]]; then
        log_info "To apply new defaults, back up and delete the existing config, then re-run"
    fi
fi

# --- Step 6: Install log rotation ---
log_info "Installing log rotation (newsyslog)"
mkdir -p /etc/newsyslog.d
cat > "$NEWSYSLOG_CONF" << 'CONF'
# EDR Graph Agent log rotation
# logfile                          mode count size(KB) when  flags
/var/log/edr-graph/agent.log  root:wheel  640  5  10240  *  J
/var/log/edr-graph/agent.err  root:wheel  640  5  1024   *  J
CONF

# --- Step 7: Install plist ---
log_info "Installing LaunchDaemon"
cp "$INSTALL_DIR/deploy/${PLIST_NAME}.plist" "$PLIST_DEST"

# Substitute API key placeholder
if [[ -n "$API_KEY" ]]; then
    sed -i '' "s|__DEEPINFRA_API_KEY__|${API_KEY}|g" "$PLIST_DEST"
else
    log_warn "No --api-key provided; set DEEPINFRA_API_KEY in the plist manually:"
    log_warn "  sudo sed -i '' 's|__DEEPINFRA_API_KEY__|YOUR_KEY|' $PLIST_DEST"
fi

chown root:wheel "$PLIST_DEST"
chmod 644 "$PLIST_DEST"

# Validate plist
if command -v plutil &>/dev/null; then
    if ! plutil -lint "$PLIST_DEST" &>/dev/null; then
        log_error "Plist validation failed"
        plutil -lint "$PLIST_DEST"
        exit 1
    fi
fi

# --- Step 8: Install management CLI ---
log_info "Installing edr-agent CLI to /usr/local/bin"
cp "$INSTALL_DIR/deploy/edr-agent" /usr/local/bin/edr-agent
chmod 755 /usr/local/bin/edr-agent

# Install tray icon LaunchAgent for the console user
CONSOLE_USER=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" 2>/dev/null \
    | awk '/Name :/ && !/loginwindow/ {print $3}')
if [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]]; then
    CONSOLE_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    if [[ -n "$CONSOLE_HOME" ]]; then
        # Find a Python 3 for the tray helper (user-accessible, not root's venv)
        TRAY_PYTHON=""
        for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
            if sudo -u "$CONSOLE_USER" "$candidate" -c "import sys" 2>/dev/null; then
                TRAY_PYTHON="$candidate"
                break
            fi
        done

        if [[ -n "$TRAY_PYTHON" ]]; then
            # Create a dedicated tray venv (user-owned, avoids PEP 668 issues)
            TRAY_VENV="/opt/edr-graph-tray"
            if [[ ! -f "$TRAY_VENV/bin/python3" ]]; then
                log_info "Creating tray icon venv at $TRAY_VENV"
                "$TRAY_PYTHON" -m venv "$TRAY_VENV"
                chown -R "$CONSOLE_USER:staff" "$TRAY_VENV"
            fi
            if ! "$TRAY_VENV/bin/python3" -c "import rumps" 2>/dev/null; then
                log_info "Installing rumps in tray venv"
                sudo -u "$CONSOLE_USER" "$TRAY_VENV/bin/pip" install --quiet rumps 2>/dev/null || \
                    log_warn "Failed to install rumps — tray icon may not work"
            fi

            TRAY_PYTHON_BIN="$TRAY_VENV/bin/python3"
            TRAY_SCRIPT="$INSTALL_DIR/agent/tray/tray_helper.py"
            TRAY_AGENTS_DIR="$CONSOLE_HOME/Library/LaunchAgents"
            TRAY_PLIST_DEST="$TRAY_AGENTS_DIR/com.edgeaspect.edr-graph-tray.plist"
            mkdir -p "$TRAY_AGENTS_DIR"
            cp "$INSTALL_DIR/deploy/com.edgeaspect.edr-graph-tray.plist" "$TRAY_PLIST_DEST"
            # Substitute placeholders
            sed -i '' "s|__TRAY_PYTHON__|${TRAY_PYTHON_BIN}|g" "$TRAY_PLIST_DEST"
            sed -i '' "s|__TRAY_SCRIPT__|${TRAY_SCRIPT}|g" "$TRAY_PLIST_DEST"
            chown "$CONSOLE_USER" "$TRAY_PLIST_DEST"
            chmod 644 "$TRAY_PLIST_DEST"
            # Make tray script readable by the user
            chmod 755 "$TRAY_SCRIPT"
            log_info "Installed tray icon LaunchAgent for user $CONSOLE_USER"
        else
            log_warn "No user-accessible Python 3 found — tray icon not installed"
        fi
    fi
else
    log_warn "No GUI user detected — tray icon plist not installed"
    log_warn "Start manually after login: sudo edr-agent start"
fi

# --- Step 9: Set permissions ---
log_info "Setting permissions"
chmod 750 "$INSTALL_DIR"
chmod 700 "$DATA_DIR"
chmod 700 "$QUARANTINE_DIR"
chmod 700 "$LOG_DIR"
chmod 600 "$CONFIG_DIR/config.yaml"

# Ensure log files exist for launchd
touch "$LOG_DIR/agent.log" "$LOG_DIR/agent.err"

# --- Step 10: Start service ---
if [[ "$NO_START" == true ]]; then
    log_info "Skipping daemon start (--no-start)"
else
    log_info "Starting daemon"
    # Try bootstrap (modern API), retry once if launchd race condition
    STARTED=false
    for _attempt in 1 2; do
        if launchctl bootstrap system "$PLIST_DEST" 2>/dev/null; then
            STARTED=true
            break
        fi
        # bootstrap failed — check if launchd already auto-loaded the plist
        if launchctl print "system/${PLIST_NAME}" &>/dev/null; then
            STARTED=true
            break
        fi
        # Wait for launchd to settle, then retry
        sleep 2
    done

    if [[ "$STARTED" != true ]]; then
        log_error "Daemon failed to start after 2 attempts"
        log_error "Try manually: sudo edr-agent start"
        exit 1
    fi

    # --- Step 11: Verify ---
    log_info "Waiting for daemon to start..."
    sleep 5

    if launchctl print "system/${PLIST_NAME}" &>/dev/null; then
        log_info "Daemon is loaded"
    else
        log_error "Daemon failed to load"
        exit 1
    fi

    # Check health endpoint
    if curl -sf http://127.0.0.1:9100/health &>/dev/null; then
        log_info "Health endpoint responding on :9100"
    else
        log_warn "Health endpoint not yet responding (may still be starting)"
        log_warn "Check logs: sudo edr-agent errors"
    fi
fi

# --- Summary ---
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  EDR Graph Agent — macOS Installation Complete${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}Install:${NC}     $INSTALL_DIR"
echo -e "  ${GREEN}Config:${NC}      $CONFIG_DIR/config.yaml"
echo -e "  ${GREEN}Data:${NC}        $DATA_DIR"
echo -e "  ${GREEN}Quarantine:${NC}  $QUARANTINE_DIR"
echo -e "  ${GREEN}Logs:${NC}        $LOG_DIR/agent.log"
echo -e "  ${GREEN}Errors:${NC}      $LOG_DIR/agent.err"
echo -e "  ${GREEN}Plist:${NC}       $PLIST_DEST"
echo ""
echo -e "  ${YELLOW}Management:${NC}"
echo -e "    sudo edr-agent restart"
echo -e "    sudo edr-agent stop"
echo -e "    sudo edr-agent start"
echo -e "    sudo edr-agent status"
echo -e "    sudo edr-agent logs"
echo -e "    sudo edr-agent errors"
echo -e "    sudo edr-agent health"
echo ""
echo -e "  ${YELLOW}Endpoints:${NC}"
echo -e "    Health:    http://127.0.0.1:9100/health"
echo -e "    Dashboard: http://127.0.0.1:9200/"
echo ""
echo -e "  ${YELLOW}Important:${NC}"
echo -e "    Grant Full Disk Access to /opt/edr-graph/.venv/bin/python3"
echo -e "    in System Settings > Privacy & Security > Full Disk Access"
echo -e "    (required for file monitoring and process inspection)"
echo ""
