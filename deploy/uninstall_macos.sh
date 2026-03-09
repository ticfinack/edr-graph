#!/usr/bin/env bash
# EDR Graph Agent — macOS Uninstaller
#
# Usage:
#   sudo bash deploy/uninstall_macos.sh [--purge]
#
# Default:  Removes daemon, install dir, log rotation.
#           Preserves config (/etc/edr-graph), data (/var/lib/edr-graph),
#           quarantine (/var/edr-graph), and logs (/var/log/edr-graph).
#
# --purge:  Removes everything including config, data, quarantine, and logs.

set -euo pipefail

PLIST_NAME="com.edgeaspect.edr-graph"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}.plist"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --- Parse arguments ---
PURGE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)
            PURGE=true; shift ;;
        -h|--help)
            head -n 13 "$0" | tail -n 12
            exit 0 ;;
        *)
            log_error "Unknown option: $1"
            exit 1 ;;
    esac
done

# --- Pre-flight checks ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    log_error "This uninstaller is for macOS only"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo -e "${YELLOW}EDR Graph Agent — macOS Uninstaller${NC}"
if [[ "$PURGE" == true ]]; then
    echo -e "${RED}Mode: PURGE (all data will be removed)${NC}"
else
    echo "Mode: Standard (config and data preserved)"
fi
echo ""

# --- Step 1: Stop daemon ---
if launchctl print "system/${PLIST_NAME}" &>/dev/null; then
    log_info "Stopping daemon"
    launchctl bootout "system/${PLIST_NAME}" 2>/dev/null || \
        launchctl unload -w "$PLIST_DEST" 2>/dev/null || true
    sleep 1
    log_info "Daemon stopped"
else
    log_info "Daemon not running"
fi

# --- Step 2: Remove tray icon LaunchAgent ---
CONSOLE_USER=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" 2>/dev/null \
    | awk '/Name :/ && !/loginwindow/ {print $3}')
TRAY_PLIST_NAME="com.edgeaspect.edr-graph-tray"
if [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]]; then
    CONSOLE_UID=$(id -u "$CONSOLE_USER" 2>/dev/null || true)
    if [[ -n "$CONSOLE_UID" ]]; then
        launchctl bootout "gui/${CONSOLE_UID}/${TRAY_PLIST_NAME}" 2>/dev/null || true
    fi
    CONSOLE_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    TRAY_PLIST="$CONSOLE_HOME/Library/LaunchAgents/${TRAY_PLIST_NAME}.plist"
    if [[ -f "$TRAY_PLIST" ]]; then
        rm -f "$TRAY_PLIST"
        log_info "Removed tray icon LaunchAgent"
    fi
fi

# --- Step 3: Remove daemon plist ---
if [[ -f "$PLIST_DEST" ]]; then
    rm -f "$PLIST_DEST"
    log_info "Removed $PLIST_DEST"
else
    log_info "Plist not found (already removed)"
fi

# --- Step 4: Remove management CLI ---
if [[ -f /usr/local/bin/edr-agent ]]; then
    rm -f /usr/local/bin/edr-agent
    log_info "Removed /usr/local/bin/edr-agent"
fi

# --- Step 4b: Remove tray venv ---
if [[ -d /opt/edr-graph-tray ]]; then
    rm -rf /opt/edr-graph-tray
    log_info "Removed /opt/edr-graph-tray"
fi

# --- Step 5: Remove install directory ---
if [[ -d /opt/edr-graph ]]; then
    rm -rf /opt/edr-graph
    log_info "Removed /opt/edr-graph"
else
    log_info "/opt/edr-graph not found (already removed)"
fi

# --- Step 6: Remove log rotation config ---
if [[ -f /etc/newsyslog.d/edr-graph.conf ]]; then
    rm -f /etc/newsyslog.d/edr-graph.conf
    log_info "Removed /etc/newsyslog.d/edr-graph.conf"
fi

# --- Step 7: Purge (optional) ---
if [[ "$PURGE" == true ]]; then
    log_info "Purging config, data, quarantine, and logs"

    if [[ -d /etc/edr-graph ]]; then
        rm -rf /etc/edr-graph
        log_info "Removed /etc/edr-graph"
    fi

    if [[ -d /var/lib/edr-graph ]]; then
        rm -rf /var/lib/edr-graph
        log_info "Removed /var/lib/edr-graph"
    fi

    if [[ -d /var/edr-graph ]]; then
        rm -rf /var/edr-graph
        log_info "Removed /var/edr-graph"
    fi

    if [[ -d /var/log/edr-graph ]]; then
        rm -rf /var/log/edr-graph
        log_info "Removed /var/log/edr-graph"
    fi
else
    echo ""
    log_info "Preserved (use --purge to remove):"
    [[ -d /etc/edr-graph ]]     && log_info "  /etc/edr-graph/       (config)"
    [[ -d /var/lib/edr-graph ]] && log_info "  /var/lib/edr-graph/   (data)"
    [[ -d /var/edr-graph ]]     && log_info "  /var/edr-graph/       (quarantine)"
    [[ -d /var/log/edr-graph ]] && log_info "  /var/log/edr-graph/   (logs)"
fi

echo ""
log_info "EDR Graph Agent uninstalled successfully"
