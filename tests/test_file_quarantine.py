"""Tests for Phase 3 Commit 4: File Quarantine (3D)."""

import hashlib
import json
import stat
from pathlib import Path

import pytest

from agent.response.file_quarantine import (
    FileQuarantine,
    QuarantineResult,
)


@pytest.fixture
def quarantine_env(tmp_path):
    """Create a quarantine environment with a test file."""
    quarantine_dir = tmp_path / "quarantine"
    test_file = tmp_path / "suspicious.exe"
    test_file.write_bytes(b"malicious content here")
    test_file.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    return FileQuarantine(quarantine_dir), str(test_file), quarantine_dir


class TestQuarantine:
    def test_quarantine_success(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        outcome = fq.quarantine(test_file)

        assert outcome.result == QuarantineResult.SUCCESS
        assert outcome.file_path == test_file
        assert outcome.action == "quarantine"
        assert outcome.sha256 != ""
        assert outcome.quarantine_path != ""
        # Original file should be gone
        assert not Path(test_file).exists()
        # Quarantined file should exist
        assert Path(outcome.quarantine_path).exists()

    def test_quarantine_computes_correct_sha256(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        expected = hashlib.sha256(b"malicious content here").hexdigest()
        outcome = fq.quarantine(test_file)
        assert outcome.sha256 == expected

    def test_quarantine_strips_execute_permissions(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        outcome = fq.quarantine(test_file)
        qpath = Path(outcome.quarantine_path)
        mode = qpath.stat().st_mode
        # Execute bits should be cleared
        assert not (mode & stat.S_IXUSR)
        assert not (mode & stat.S_IXGRP)
        assert not (mode & stat.S_IXOTH)
        # Read should be preserved
        assert mode & stat.S_IRUSR

    def test_quarantine_writes_metadata_sidecar(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        outcome = fq.quarantine(test_file)
        meta_path = Path(outcome.quarantine_path + ".meta")
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["original_path"] == test_file
        assert meta["sha256"] == outcome.sha256
        assert "timestamp" in meta

    def test_quarantine_nonexistent_file(self, quarantine_env):
        fq, _, qdir = quarantine_env
        outcome = fq.quarantine("/nonexistent/path.exe")
        assert outcome.result == QuarantineResult.NOT_FOUND

    def test_quarantine_already_quarantined(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        fq.quarantine(test_file)
        outcome = fq.quarantine(test_file)
        assert outcome.result == QuarantineResult.ALREADY_QUARANTINED

    def test_quarantine_creates_dir(self, tmp_path):
        """Quarantine directory is created on first use."""
        qdir = tmp_path / "does_not_exist" / "quarantine"
        fq = FileQuarantine(qdir)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"data")
        fq.quarantine(str(test_file))
        assert qdir.exists()


class TestRestore:
    def test_restore_success(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        fq.quarantine(test_file)
        outcome = fq.restore(test_file)

        assert outcome.result == QuarantineResult.SUCCESS
        assert outcome.file_path == test_file
        assert outcome.action == "restore"
        # File should be back at original location
        assert Path(test_file).exists()
        # Content should be unchanged
        assert Path(test_file).read_bytes() == b"malicious content here"

    def test_restore_preserves_original_permissions(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        original_mode = Path(test_file).stat().st_mode
        fq.quarantine(test_file)
        fq.restore(test_file)
        restored_mode = Path(test_file).stat().st_mode
        assert restored_mode == original_mode

    def test_restore_removes_metadata_sidecar(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        outcome = fq.quarantine(test_file)
        meta_path = Path(outcome.quarantine_path + ".meta")
        assert meta_path.exists()
        fq.restore(test_file)
        assert not meta_path.exists()

    def test_restore_not_quarantined(self, quarantine_env):
        fq, _, qdir = quarantine_env
        outcome = fq.restore("/some/random/file.exe")
        assert outcome.result == QuarantineResult.NOT_QUARANTINED

    def test_restore_missing_quarantine_file(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        outcome = fq.quarantine(test_file)
        # Delete the quarantined file manually
        Path(outcome.quarantine_path).unlink()
        restore_outcome = fq.restore(test_file)
        assert restore_outcome.result == QuarantineResult.NOT_FOUND


class TestFileQuarantineState:
    def test_initially_empty(self, tmp_path):
        fq = FileQuarantine(tmp_path / "q")
        assert fq.quarantined_files == set()

    def test_is_quarantined(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        assert not fq.is_quarantined(test_file)
        fq.quarantine(test_file)
        assert fq.is_quarantined(test_file)

    def test_get_record(self, quarantine_env):
        fq, test_file, qdir = quarantine_env
        assert fq.get_record(test_file) is None
        fq.quarantine(test_file)
        record = fq.get_record(test_file)
        assert record is not None
        assert record.original_path == test_file
        assert record.sha256 != ""
        assert record.timestamp > 0

    def test_multiple_files(self, tmp_path):
        qdir = tmp_path / "quarantine"
        fq = FileQuarantine(qdir)
        files = []
        for i in range(3):
            f = tmp_path / f"file{i}.bin"
            f.write_bytes(f"content {i}".encode())
            files.append(str(f))
            fq.quarantine(str(f))
        assert fq.quarantined_files == set(files)


class TestQuarantineResultEnum:
    def test_all_values(self):
        assert QuarantineResult.SUCCESS.value == "success"
        assert QuarantineResult.NOT_FOUND.value == "not_found"
        assert QuarantineResult.PERMISSION_DENIED.value == "permission_denied"
        assert QuarantineResult.FAILED.value == "failed"
        assert QuarantineResult.ALREADY_QUARANTINED.value == "already_quarantined"
        assert QuarantineResult.NOT_QUARANTINED.value == "not_quarantined"
