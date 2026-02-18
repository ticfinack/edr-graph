"""Tamper detection for agent self-protection.

On startup, computes SHA256 hashes of all agent source files.
Periodically re-verifies these hashes and raises a CRITICAL alert
if any files have been modified.

On Windows, also monitors the service registry key for unauthorized changes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TamperEvent:
    """Record of a detected file tampering."""

    file_path: str
    expected_hash: str
    actual_hash: str
    timestamp: float
    event_type: str  # "modified", "deleted", "new"


@dataclass
class TamperCheckResult:
    """Result of a tamper verification cycle."""

    checked_files: int
    tampered_files: list[TamperEvent] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return (
            not self.tampered_files
            and not self.new_files
            and not self.deleted_files
        )


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def scan_agent_files(agent_dir: Path) -> dict[str, str]:
    """Scan all Python files in the agent directory and compute their hashes.

    Returns a dict mapping relative file paths to their SHA256 hashes.
    """
    hashes: dict[str, str] = {}

    if not agent_dir.exists():
        logger.warning("Agent directory does not exist: %s", agent_dir)
        return hashes

    for py_file in sorted(agent_dir.rglob("*.py")):
        # Skip __pycache__ directories
        if "__pycache__" in str(py_file):
            continue

        rel_path = str(py_file.relative_to(agent_dir.parent))
        file_hash = compute_file_hash(py_file)
        if file_hash:
            hashes[rel_path] = file_hash

    return hashes


def verify_integrity(
    baseline: dict[str, str],
    agent_dir: Path,
) -> TamperCheckResult:
    """Compare current file hashes against the baseline.

    Returns a TamperCheckResult with any modifications, additions, or deletions.
    """
    current = scan_agent_files(agent_dir)
    result = TamperCheckResult(checked_files=len(current))

    # Check for modified and deleted files
    for rel_path, expected_hash in baseline.items():
        if rel_path not in current:
            result.deleted_files.append(rel_path)
            result.tampered_files.append(
                TamperEvent(
                    file_path=rel_path,
                    expected_hash=expected_hash,
                    actual_hash="",
                    timestamp=time.time(),
                    event_type="deleted",
                )
            )
        elif current[rel_path] != expected_hash:
            result.tampered_files.append(
                TamperEvent(
                    file_path=rel_path,
                    expected_hash=expected_hash,
                    actual_hash=current[rel_path],
                    timestamp=time.time(),
                    event_type="modified",
                )
            )

    # Check for new files
    for rel_path in current:
        if rel_path not in baseline:
            result.new_files.append(rel_path)

    return result


class TamperChecker:
    """Periodically verifies agent file integrity."""

    def __init__(
        self,
        agent_dir: Path,
        check_interval: float = 60.0,
        on_tamper: callable | None = None,
    ) -> None:
        self.agent_dir = agent_dir
        self.check_interval = check_interval
        self.on_tamper = on_tamper
        self._baseline: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._check_count = 0
        self._tamper_count = 0

    @property
    def baseline(self) -> dict[str, str]:
        """Return the current baseline hashes."""
        return dict(self._baseline)

    @property
    def check_count(self) -> int:
        return self._check_count

    @property
    def tamper_count(self) -> int:
        return self._tamper_count

    def initialize_baseline(self) -> int:
        """Scan agent files and establish the baseline.

        Returns the number of files in the baseline.
        """
        self._baseline = scan_agent_files(self.agent_dir)
        logger.info(
            "Tamper detection baseline: %d files in %s",
            len(self._baseline),
            self.agent_dir,
        )
        return len(self._baseline)

    def check_once(self) -> TamperCheckResult:
        """Run a single integrity verification check."""
        result = verify_integrity(self._baseline, self.agent_dir)
        self._check_count += 1

        if not result.is_clean:
            self._tamper_count += 1
            for event in result.tampered_files:
                logger.critical(
                    "TAMPER DETECTED: %s %s (expected %s, got %s)",
                    event.event_type,
                    event.file_path,
                    event.expected_hash[:16] + "...",
                    (event.actual_hash[:16] + "...") if event.actual_hash else "DELETED",
                )

            for new_file in result.new_files:
                logger.warning("New file detected in agent directory: %s", new_file)

            if self.on_tamper:
                self.on_tamper(result)

        return result

    def start(self) -> None:
        """Start periodic integrity checks in a background thread."""
        if self._thread is not None:
            return

        self.initialize_baseline()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._check_loop, daemon=True, name="tamper-checker"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop periodic integrity checks."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _check_loop(self) -> None:
        """Background loop for periodic checks."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.check_interval)
            if self._stop_event.is_set():
                break
            try:
                self.check_once()
            except Exception:
                logger.exception("Tamper check failed")


def check_windows_service_registry(
    service_name: str = "EDRGraphAgent",
) -> dict | None:
    """Check the Windows service registry key for unauthorized modifications.

    Returns a dict with service config if available, None on non-Windows.
    """
    if os.name != "nt":
        return None

    try:
        import winreg

        key_path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            config = {}
            for name in ("ImagePath", "Start", "Type", "ObjectName"):
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                    config[name] = value
                except FileNotFoundError:
                    pass
            return config
    except Exception:
        return None
