from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Application settings, overridable via environment variables."""

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
