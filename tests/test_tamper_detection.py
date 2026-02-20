"""Tests for Phase 4 Commit 4: Tamper Detection (4D)."""

import hashlib
import time

import pytest

from agent.platform.tamper_detection import (
    TamperChecker,
    TamperCheckResult,
    TamperEvent,
    compute_file_hash,
    scan_agent_files,
    verify_integrity,
)


@pytest.fixture
def fake_agent_dir(tmp_path):
    """Create a fake agent directory with Python files."""
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "__init__.py").write_text("")
    (agent_dir / "main.py").write_text("print('hello')")
    sub = agent_dir / "sub"
    sub.mkdir()
    (sub / "__init__.py").write_text("")
    (sub / "module.py").write_text("x = 42")
    # Add a __pycache__ file that should be ignored
    cache = agent_dir / "__pycache__"
    cache.mkdir()
    (cache / "main.cpython-313.pyc").write_bytes(b"\x00\x00")
    return agent_dir


class TestComputeFileHash:
    def test_computes_correct_sha256(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert compute_file_hash(f) == expected

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_file_hash(f) == expected

    def test_nonexistent_file_returns_empty(self, tmp_path):
        assert compute_file_hash(tmp_path / "nope.py") == ""


class TestScanAgentFiles:
    def test_scans_all_python_files(self, fake_agent_dir):
        hashes = scan_agent_files(fake_agent_dir)
        assert len(hashes) == 4  # __init__.py, main.py, sub/__init__.py, sub/module.py

    def test_excludes_pycache(self, fake_agent_dir):
        hashes = scan_agent_files(fake_agent_dir)
        for path in hashes:
            assert "__pycache__" not in path

    def test_relative_paths(self, fake_agent_dir):
        hashes = scan_agent_files(fake_agent_dir)
        for path in hashes:
            assert path.startswith("agent/")

    def test_nonexistent_dir_returns_empty(self, tmp_path):
        hashes = scan_agent_files(tmp_path / "nonexistent")
        assert hashes == {}


class TestVerifyIntegrity:
    def test_clean_check(self, fake_agent_dir):
        baseline = scan_agent_files(fake_agent_dir)
        result = verify_integrity(baseline, fake_agent_dir)
        assert result.is_clean
        assert result.checked_files == 4
        assert result.tampered_files == []

    def test_detects_modified_file(self, fake_agent_dir):
        baseline = scan_agent_files(fake_agent_dir)
        # Modify a file
        (fake_agent_dir / "main.py").write_text("print('hacked!')")
        result = verify_integrity(baseline, fake_agent_dir)
        assert not result.is_clean
        assert len(result.tampered_files) == 1
        assert result.tampered_files[0].event_type == "modified"
        assert "main.py" in result.tampered_files[0].file_path

    def test_detects_deleted_file(self, fake_agent_dir):
        baseline = scan_agent_files(fake_agent_dir)
        (fake_agent_dir / "main.py").unlink()
        result = verify_integrity(baseline, fake_agent_dir)
        assert not result.is_clean
        assert len(result.deleted_files) == 1
        assert any(e.event_type == "deleted" for e in result.tampered_files)

    def test_detects_new_file(self, fake_agent_dir):
        baseline = scan_agent_files(fake_agent_dir)
        (fake_agent_dir / "backdoor.py").write_text("evil()")
        result = verify_integrity(baseline, fake_agent_dir)
        assert not result.is_clean
        assert len(result.new_files) == 1
        assert any("backdoor.py" in f for f in result.new_files)

    def test_multiple_changes(self, fake_agent_dir):
        baseline = scan_agent_files(fake_agent_dir)
        (fake_agent_dir / "main.py").write_text("modified")
        (fake_agent_dir / "sub" / "module.py").unlink()
        (fake_agent_dir / "new.py").write_text("new")
        result = verify_integrity(baseline, fake_agent_dir)
        assert not result.is_clean
        assert len(result.tampered_files) == 2  # 1 modified + 1 deleted
        assert len(result.new_files) == 1


class TestTamperChecker:
    def test_initialize_baseline(self, fake_agent_dir):
        checker = TamperChecker(fake_agent_dir)
        count = checker.initialize_baseline()
        assert count == 4
        assert len(checker.baseline) == 4

    def test_check_once_clean(self, fake_agent_dir):
        checker = TamperChecker(fake_agent_dir)
        checker.initialize_baseline()
        result = checker.check_once()
        assert result.is_clean
        assert checker.check_count == 1
        assert checker.tamper_count == 0

    def test_check_once_tampered(self, fake_agent_dir):
        checker = TamperChecker(fake_agent_dir)
        checker.initialize_baseline()
        (fake_agent_dir / "main.py").write_text("hacked")
        result = checker.check_once()
        assert not result.is_clean
        assert checker.tamper_count == 1

    def test_on_tamper_callback(self, fake_agent_dir):
        results = []
        checker = TamperChecker(
            fake_agent_dir,
            on_tamper=lambda r: results.append(r),
        )
        checker.initialize_baseline()
        (fake_agent_dir / "main.py").write_text("hacked")
        checker.check_once()
        assert len(results) == 1
        assert not results[0].is_clean

    def test_start_and_stop(self, fake_agent_dir):
        checker = TamperChecker(fake_agent_dir, check_interval=0.1)
        checker.start()
        assert checker._thread is not None
        time.sleep(0.3)
        checker.stop()
        assert checker.check_count >= 1


class TestTamperEvent:
    def test_event_fields(self):
        event = TamperEvent(
            file_path="agent/main.py",
            expected_hash="aaa",
            actual_hash="bbb",
            timestamp=1700000000.0,
            event_type="modified",
        )
        assert event.file_path == "agent/main.py"
        assert event.event_type == "modified"


class TestTamperCheckResult:
    def test_clean_result(self):
        result = TamperCheckResult(checked_files=10)
        assert result.is_clean

    def test_dirty_result(self):
        result = TamperCheckResult(
            checked_files=10,
            tampered_files=[TamperEvent("f", "a", "b", 0.0, "modified")],
        )
        assert not result.is_clean
