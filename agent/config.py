"""Application configuration with YAML file support.

Priority chain (highest to lowest):
    1. CLI arguments (applied after loading)
    2. Environment variables
    3. Config file (config.yaml)
    4. Pydantic defaults
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load .env from project root (won't override existing env vars)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


class Settings(BaseModel):
    """Application settings, overridable via environment variables or config file."""

    data_dir: Path = Field(default_factory=lambda: Path(os.environ.get("EDR_DATA_DIR", "./edr_data")))
    deepinfra_api_key: str = Field(default_factory=lambda: os.environ.get("DEEPINFRA_API_KEY", ""))
    deepinfra_model: str = "google/gemma-3-27b-it"
    deepinfra_base_url: str = "https://api.deepinfra.com/v1/openai"

    collector_poll_interval: float = 1.0  # seconds
    processor_poll_interval: float = 2.0  # seconds
    analyzer_interval: float = 60.0  # seconds
    processor_batch_size: int = 500

    # Retention settings
    event_retention_hours: int = 24  # Auto-prune processed events older than this

    dashboard_port: int = 9200
    dashboard_refresh_interval: float = 5.0  # seconds
    dashboard_auto_open: bool = True  # Open dashboard in browser on startup
    metrics_port: int = 9100

    # Tray icon settings (macOS only)
    tray_enabled: bool = True
    tray_notification_cooldown: int = 60  # seconds
    tray_notify_on_high: bool = True
    tray_notify_on_critical: bool = True

    file_read_tracking: bool = False  # Enable (:Process)-[:READ]->(:File) edges. High volume.

    # DGA detection settings
    dga_entropy_threshold: float = 3.5
    dga_score_threshold: float = 0.6
    dga_allowlist: list[str] = [
        "googleapis.com",
        "cloudflare.com",
        "amazonaws.com",
        "windows.net",
        "office365.com",
        "microsoftonline.com",
    ]

    # Response engine settings
    response_mode: str = "passive"  # "learning" (baseline only), "active" (enforce), "passive" (alert only)
    auto_respond: bool = False  # Auto-execute response actions for CRITICAL severity
    auto_terminate: bool = False  # Allow process termination without human approval
    quarantine_dir: Path = Field(
        default_factory=lambda: Path(
            os.environ.get(
                "EDR_QUARANTINE_DIR",
                "C:\\ProgramData\\edr-graph\\quarantine" if os.name == "nt" else "/var/edr-graph/quarantine",
            )
        )
    )

    # Self-protection settings
    watchdog_enabled: bool = True
    heartbeat_interval: float = 10.0  # seconds
    heartbeat_dir: Path = Field(
        default_factory=lambda: Path(os.environ.get("EDR_HEARTBEAT_DIR", "/tmp/edr-heartbeats"))
    )
    tamper_check_enabled: bool = True
    tamper_check_interval: float = 60.0  # seconds

    baseline_graph_gating: bool = True  # Filter baselined edges from graph in non-learning modes

    graph_max_memory_mb: int = 512  # KùzuDB buffer pool size limit
    graph_ttl_hours: int = 24  # Delete graph edges older than this

    novel_edge_threshold: int = 5
    graph_context_limit: int = 20

    # Enrichment settings
    process_identity_enabled: bool = True
    process_identity_cache_size: int = 500
    port_mapper_refresh_interval: float = 30.0
    allowlist_enabled: bool = True
    allowlist_custom_entries: list[dict] = []

    # Connection metadata settings
    connection_metadata_enabled: bool = True
    connection_metadata_capture_sni: bool = True
    connection_metadata_compute_ja3: bool = True
    connection_metadata_retention_hours: int = 24

    # IOC feed settings
    ioc_feeds_enabled: bool = True
    ioc_feeds_refresh_hours: int = 4
    ioc_exclusion_patterns: list[str] = Field(default_factory=list)

    # Investigation tools (Tier 4 — safe, read-only local host inspection)
    investigation_tools_enabled: bool = True

    # Tool-use settings
    tool_use_enabled: bool = True
    tool_use_max_iterations: int = 5
    abuseipdb_api_key: str = Field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", ""))
    virustotal_api_key: str = Field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))

    # Fleet forwarding settings
    fleet_enabled: bool = False
    fleet_url: str = ""  # Central server address, e.g. "fleet.example.com:50051"
    fleet_agent_id: str = Field(default_factory=lambda: os.environ.get("EDR_AGENT_ID", ""))
    fleet_ca_cert: str = ""  # Path to CA certificate for mTLS
    fleet_client_cert: str = ""  # Path to client certificate
    fleet_client_key: str = ""  # Path to client private key
    fleet_forward_interval: float = 10.0  # Seconds between forwarding cycles
    fleet_forward_events: bool = False  # Forward raw OCSF events (high volume)
    fleet_heartbeat_interval: float = 30.0  # Seconds between heartbeats
    fleet_queue_max_size: int = 10000  # Max items buffered in forwarding queue
    fleet_retry_max: int = 5  # Max retries per queued item
    fleet_registration_key: str = Field(default_factory=lambda: os.environ.get("EDR_REGISTRATION_KEY", ""))

    # NTP clock synchronization (for fleet time correlation)
    ntp_server: str = "pool.ntp.org"
    ntp_sync_interval: int = 300  # seconds

    @property
    def db_path(self) -> Path:
        return self.data_dir / "queue.db"

    @property
    def graph_path(self) -> Path:
        return self.data_dir / "graph"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # Don't create graph_path — kuzu.Database creates it itself


# --- YAML config file mapping ---
# Maps nested YAML keys to flat Settings field names.

_YAML_KEY_MAP: dict[tuple[str, ...], str] = {
    ("agent", "log_level"): "_log_level",  # Handled by CLI, not Settings
    ("agent", "log_format"): "_log_format",
    ("collector", "poll_interval"): "collector_poll_interval",
    ("collector", "buffer_size"): "processor_batch_size",
    ("collector", "event_retention_hours"): "event_retention_hours",
    ("analysis", "llm", "model"): "deepinfra_model",
    ("analysis", "llm", "api_key_env"): "_api_key_env",
    ("analysis", "dga", "entropy_threshold"): "dga_entropy_threshold",
    ("analysis", "dga", "score_threshold"): "dga_score_threshold",
    ("analysis", "dga", "allowlist"): "dga_allowlist",
    ("response", "mode"): "response_mode",
    ("response", "baseline_graph_gating"): "baseline_graph_gating",
    ("response", "auto_respond"): "auto_respond",
    ("response", "auto_terminate"): "auto_terminate",
    ("response", "quarantine_dir"): "quarantine_dir",
    ("persistence", "watchdog_enabled"): "watchdog_enabled",
    ("persistence", "heartbeat_interval_seconds"): "heartbeat_interval",
    ("persistence", "tamper_check_interval_seconds"): "tamper_check_interval",
    ("metrics", "port"): "metrics_port",
    ("metrics", "enabled"): "_metrics_enabled",
    ("dashboard", "port"): "dashboard_port",
    ("dashboard", "refresh_interval"): "dashboard_refresh_interval",
    ("dashboard", "auto_open_browser"): "dashboard_auto_open",
    ("tray", "enabled"): "tray_enabled",
    ("tray", "notification_cooldown_seconds"): "tray_notification_cooldown",
    ("tray", "notify_on_high"): "tray_notify_on_high",
    ("tray", "notify_on_critical"): "tray_notify_on_critical",
    ("enrichment", "process_identity", "enabled"): "process_identity_enabled",
    ("enrichment", "process_identity", "cache_size"): "process_identity_cache_size",
    ("enrichment", "port_mapper", "refresh_interval_seconds"): "port_mapper_refresh_interval",
    ("enrichment", "allowlist", "enabled"): "allowlist_enabled",
    ("enrichment", "allowlist", "custom_entries"): "allowlist_custom_entries",
    ("enrichment", "connection_metadata", "enabled"): "connection_metadata_enabled",
    ("enrichment", "connection_metadata", "retention_hours"): "connection_metadata_retention_hours",
    ("fleet", "enabled"): "fleet_enabled",
    ("fleet", "url"): "fleet_url",
    ("fleet", "agent_id"): "fleet_agent_id",
    ("fleet", "ca_cert"): "fleet_ca_cert",
    ("fleet", "client_cert"): "fleet_client_cert",
    ("fleet", "client_key"): "fleet_client_key",
    ("fleet", "forward_interval"): "fleet_forward_interval",
    ("fleet", "forward_events"): "fleet_forward_events",
    ("fleet", "heartbeat_interval"): "fleet_heartbeat_interval",
    ("fleet", "queue_max_size"): "fleet_queue_max_size",
    ("fleet", "retry_max"): "fleet_retry_max",
    ("fleet", "registration_key"): "fleet_registration_key",
    ("fleet", "ntp_server"): "ntp_server",
    ("fleet", "ntp_sync_interval"): "ntp_sync_interval",
    ("graph", "max_memory_mb"): "graph_max_memory_mb",
    ("graph", "ttl_hours"): "graph_ttl_hours",
    ("analysis", "ioc_feeds_enabled"): "ioc_feeds_enabled",
    ("analysis", "ioc_feeds_refresh_hours"): "ioc_feeds_refresh_hours",
}


_MISSING = object()


def _get_nested(data: dict, keys: tuple[str, ...]) -> Any:
    """Traverse nested dict by key path. Returns _MISSING sentinel if not found."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return _MISSING
        current = current.get(key, _MISSING)
        if current is _MISSING:
            return _MISSING
    return current


def load_config_file(config_path: Path) -> dict[str, Any]:
    """Load a YAML config file and return a flat dict of Settings overrides.

    Only returns keys that are actually present in the file, so that
    defaults and env vars are preserved for unspecified settings.
    """
    if not config_path.exists():
        return {}

    with open(config_path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return {}

    overrides: dict[str, Any] = {}

    for yaml_keys, settings_field in _YAML_KEY_MAP.items():
        value = _get_nested(data, yaml_keys)
        if value is not _MISSING:
            # Skip internal/meta fields (prefixed with _)
            if settings_field.startswith("_"):
                continue
            overrides[settings_field] = value

    # Handle data_dir from top-level or agent section
    for keys in [("agent", "data_dir"), ("data_dir",)]:
        value = _get_nested(data, keys)
        if value is not _MISSING:
            overrides["data_dir"] = value
            break

    return overrides


def load_settings(config_path: Path | None = None) -> Settings:
    """Load settings from config file, with env var overrides.

    Priority: env vars > config file > defaults.
    CLI args should be applied after this call.

    If config_path is None, looks for config files at:
    - /etc/edr-graph/config.yaml (Linux/macOS system-wide)
    - C:\\ProgramData\\edr-graph\\config.yaml (Windows system-wide)
    """
    if config_path:
        overrides = load_config_file(config_path)
    else:
        # Try system-wide default locations only (not CWD — avoids test pollution)
        system_paths = [Path("/etc/edr-graph/config.yaml")]
        if os.name == "nt":
            system_paths.insert(0, Path("C:\\ProgramData\\edr-graph\\config.yaml"))

        overrides = {}
        for default_path in system_paths:
            if default_path.exists():
                overrides = load_config_file(default_path)
                break

    return Settings(**overrides)


def generate_default_config() -> str:
    """Generate a config.yaml with all documented defaults."""
    return """\
# EDR Graph Agent Configuration
# Values here are overridden by environment variables and CLI arguments.

agent:
  name: "edr-graph-agent"
  log_level: "INFO"        # DEBUG, INFO, WARNING, ERROR
  log_format: "json"       # "json" or "text"
  data_dir: "./edr_data"

collector:
  poll_interval: 1.0       # seconds between collection cycles
  buffer_size: 500          # max events per processing batch
  event_retention_hours: 24  # Auto-prune processed events older than this

analysis:
  llm:
    model: "google/gemma-3-27b-it"
    api_key_env: "DEEPINFRA_API_KEY"   # Read API key from this env var
    # Never put API keys directly in this file!
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
  mode: "passive"           # "learning" (baseline only), "active" (enforce), "passive" (alert only)
  auto_respond: false       # Auto-execute response for CRITICAL severity
  auto_terminate: false     # Allow process termination without approval
  # quarantine_dir: "/var/edr-graph/quarantine"  # Platform-dependent default

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
  auto_open_browser: true     # Open dashboard in browser on startup

tray:
  enabled: true               # macOS only, ignored on other platforms
  notification_cooldown_seconds: 60
  notify_on_high: true
  notify_on_critical: true

graph:
  max_memory_mb: 512          # KùzuDB buffer pool size limit (MB)
  ttl_hours: 24               # Delete graph edges older than this (hours)

fleet:
  enabled: false              # Enable fleet forwarding to central server
  url: ""                     # Central server gRPC address (host:port)
  # agent_id: ""              # Auto-generated UUID if empty
  # ca_cert: ""               # Path to CA certificate for mTLS
  # client_cert: ""           # Path to client certificate
  # client_key: ""            # Path to client private key
  forward_interval: 10        # Seconds between forwarding cycles
  forward_events: false       # Forward raw OCSF events (high volume)
  heartbeat_interval: 30      # Seconds between heartbeats
  queue_max_size: 10000       # Max items buffered locally
  retry_max: 5                # Max retries per queued item
  ntp_server: "pool.ntp.org"  # NTP server for clock sync (fleet correlation)
  ntp_sync_interval: 300      # Seconds between NTP offset measurements
"""
