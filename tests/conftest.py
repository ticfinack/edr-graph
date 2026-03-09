"""Shared fixtures for EDR Graph tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _isolate_psutil_process():
    """Prevent psutil.Process() from resolving real PIDs during tests.

    Many tests use synthetic PIDs (e.g. 200, 400) that may coincidentally
    match running processes on the test machine. The psutil user-resolution
    fallback in get_process_chain() would then inject unexpected user entries
    into the chain. This fixture makes psutil.Process() raise for any PID
    unless the test explicitly patches it.
    """
    with patch("psutil.Process", side_effect=ProcessLookupError("test isolation")):
        yield
