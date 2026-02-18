"""File quarantine for response actions.

Moves suspicious files to a quarantine directory, strips execute permissions,
and logs metadata (original path, SHA256, timestamp) for forensic chain of custody.

Supports restore to return files to their original location.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class QuarantineResult(Enum):
    """Outcome of a quarantine operation."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    FAILED = "failed"
    ALREADY_QUARANTINED = "already_quarantined"
    NOT_QUARANTINED = "not_quarantined"


@dataclass
class QuarantineOutcome:
    """Result of a quarantine action with context."""

    result: QuarantineResult
    file_path: str
    action: str  # "quarantine" or "restore"
    quarantine_path: str = ""
    sha256: str = ""
    detail: str = ""


@dataclass
class QuarantineRecord:
    """Metadata for a quarantined file."""

    original_path: str
    quarantine_path: str
    sha256: str
    timestamp: float
    original_permissions: int


class FileQuarantine:
    """Manages file quarantine operations.

    Moves files to a quarantine directory, strips permissions, and tracks
    metadata for restore operations.
    """

    def __init__(self, quarantine_dir: Path) -> None:
        self.quarantine_dir = quarantine_dir
        # Map of original_path -> QuarantineRecord
        self._records: dict[str, QuarantineRecord] = {}

    @property
    def quarantined_files(self) -> set[str]:
        """Return the set of currently quarantined file paths."""
        return set(self._records.keys())

    def is_quarantined(self, file_path: str) -> bool:
        """Check if a file is currently quarantined."""
        return str(file_path) in self._records

    def get_record(self, file_path: str) -> QuarantineRecord | None:
        """Get the quarantine record for a file."""
        return self._records.get(str(file_path))

    def quarantine(self, file_path: str) -> QuarantineOutcome:
        """Move a file to quarantine, stripping execute permissions.

        The file is renamed with a .quarantined extension and its metadata
        (original path, SHA256, timestamp, permissions) is recorded.
        """
        file_path = str(file_path)

        if file_path in self._records:
            return QuarantineOutcome(
                result=QuarantineResult.ALREADY_QUARANTINED,
                file_path=file_path,
                action="quarantine",
                detail=f"{file_path} is already quarantined",
            )

        source = Path(file_path)
        if not source.exists():
            return QuarantineOutcome(
                result=QuarantineResult.NOT_FOUND,
                file_path=file_path,
                action="quarantine",
                detail=f"{file_path} does not exist",
            )

        try:
            # Compute SHA256 before moving
            sha256 = _compute_sha256(source)

            # Record original permissions
            original_perms = source.stat().st_mode

            # Create quarantine directory
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)

            # Build quarantine filename: timestamp_originalname.quarantined
            ts = int(time.time())
            safe_name = source.name.replace(os.sep, "_")
            quarantine_name = f"{ts}_{safe_name}.quarantined"
            quarantine_path = self.quarantine_dir / quarantine_name

            # Move file to quarantine
            shutil.move(str(source), str(quarantine_path))

            # Strip execute permissions (keep read for forensic analysis)
            quarantine_path.chmod(stat.S_IRUSR | stat.S_IRGRP)

            # Write metadata sidecar
            record = QuarantineRecord(
                original_path=file_path,
                quarantine_path=str(quarantine_path),
                sha256=sha256,
                timestamp=ts,
                original_permissions=original_perms,
            )
            self._records[file_path] = record

            metadata_path = quarantine_path.with_suffix(".quarantined.meta")
            metadata_path.write_text(
                json.dumps({
                    "original_path": record.original_path,
                    "sha256": record.sha256,
                    "timestamp": record.timestamp,
                    "original_permissions": oct(record.original_permissions),
                }),
            )

            logger.info(
                "Quarantined %s -> %s (SHA256: %s)",
                file_path,
                quarantine_path,
                sha256,
            )
            return QuarantineOutcome(
                result=QuarantineResult.SUCCESS,
                file_path=file_path,
                action="quarantine",
                quarantine_path=str(quarantine_path),
                sha256=sha256,
            )

        except PermissionError:
            return QuarantineOutcome(
                result=QuarantineResult.PERMISSION_DENIED,
                file_path=file_path,
                action="quarantine",
                detail=f"Insufficient permissions to quarantine {file_path}",
            )
        except Exception as e:
            return QuarantineOutcome(
                result=QuarantineResult.FAILED,
                file_path=file_path,
                action="quarantine",
                detail=str(e),
            )

    def restore(self, file_path: str) -> QuarantineOutcome:
        """Restore a quarantined file to its original location.

        Restores original permissions and removes the quarantine metadata.
        """
        file_path = str(file_path)

        record = self._records.get(file_path)
        if record is None:
            return QuarantineOutcome(
                result=QuarantineResult.NOT_QUARANTINED,
                file_path=file_path,
                action="restore",
                detail=f"{file_path} is not quarantined",
            )

        quarantine_path = Path(record.quarantine_path)
        if not quarantine_path.exists():
            del self._records[file_path]
            return QuarantineOutcome(
                result=QuarantineResult.NOT_FOUND,
                file_path=file_path,
                action="restore",
                detail=f"Quarantined file {quarantine_path} no longer exists",
            )

        try:
            original = Path(record.original_path)

            # Ensure parent directory exists
            original.parent.mkdir(parents=True, exist_ok=True)

            # Move back
            shutil.move(str(quarantine_path), str(original))

            # Restore original permissions
            original.chmod(record.original_permissions)

            # Remove metadata sidecar
            metadata_path = quarantine_path.with_suffix(".quarantined.meta")
            if metadata_path.exists():
                metadata_path.unlink()

            del self._records[file_path]

            logger.info("Restored %s from quarantine", file_path)
            return QuarantineOutcome(
                result=QuarantineResult.SUCCESS,
                file_path=file_path,
                action="restore",
                quarantine_path=str(quarantine_path),
                sha256=record.sha256,
            )

        except PermissionError:
            return QuarantineOutcome(
                result=QuarantineResult.PERMISSION_DENIED,
                file_path=file_path,
                action="restore",
                detail=f"Insufficient permissions to restore {file_path}",
            )
        except Exception as e:
            return QuarantineOutcome(
                result=QuarantineResult.FAILED,
                file_path=file_path,
                action="restore",
                detail=str(e),
            )


def _compute_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
