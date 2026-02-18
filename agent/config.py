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
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Application settings, overridable via environment variables or config file."""

    data_dir: Path = Field(
        default_factory=lambda: Path(os.environ.get("EDR_DATA_DIR", "./edr_data"))
    )
    deepinfra_api_key: str = Field(
        default_factory=lambda: os.environ.get("DEEPINFRA_API_KEY", "")
    )
    deepinfra_model: str = "google/gemma-3-27b-it"
    deepinfra_base_url: str = "https://api.deepinfra.com/v1/openai"

    collector_poll_interval: float = 5.0  # seconds
    processor_poll_interval: float = 2.0  # seconds
    analyzer_interval: float = 60.0  # seconds
    processor_batch_size: int = 500

    dashboard_port: int = 8080
    dashboard_refresh_interval: float = 5.0  # seconds
    metrics_port: int = 9100

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
    auto_respond: bool = False  # Auto-execute response actions for CRITICAL severity
    auto_terminate: bool = False  # Allow process termination without human approval
    quarantine_dir: Path = Field(
        default_factory=lambda: Path(
            os.environ.get(
                "EDR_QUARANTINE_DIR",
                "C:\\ProgramData\\edr-graph\\quarantine"
                if os.name == "nt"
                else "/var/edr-graph/quarantine",
            )
        )
    )

    # Self-protection settings
    watchdog_enabled: bool = True
    heartbeat_interval: float = 10.0  # seconds
    heartbeat_dir: Path = Field(
        default_factory=lambda: Path(
            os.environ.get("EDR_HEARTBEAT_DIR", "/tmp/edr-heartbeats")
        )
    )
    tamper_check_enabled: bool = True
    tamper_check_interval: float = 60.0  # seconds

    novel_edge_threshold: int = 5
    graph_context_limit: int = 20

    # Tool-use settings
    tool_use_enabled: bool = True
    tool_use_max_iterations: int = 5
    abuseipdb_api_key: str = Field(
        default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", "")
    )
    virustotal_api_key: str = Field(
        default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", "")
    )

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
    ("analysis", "llm", "model"): "deepinfra_model",
    ("analysis", "llm", "api_key_env"): "_api_key_env",
    ("analysis", "dga", "entropy_threshold"): "dga_entropy_threshold",
    ("analysis", "dga", "score_threshold"): "dga_score_threshold",
    ("analysis", "dga", "allowlist"): "dga_allowlist",
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
  poll_interval: 5.0       # seconds between collection cycles
  buffer_size: 500          # max events per processing batch

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
  port: 8080
  refresh_interval: 5.0
"""
