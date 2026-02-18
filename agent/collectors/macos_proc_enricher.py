"""macOS process command line enrichment via sysctl KERN_PROCARGS2.

Reads full command line arguments for a given PID by querying the kernel
directly through ctypes. This is the macOS equivalent of reading
/proc/{pid}/cmdline on Linux.

This is NOT a standalone collector — it's an enrichment pass called from
the processor thread when a process_start event arrives with an incomplete
command line.

Timing is critical: the enrichment must happen as quickly as possible
after the event arrives, before the process exits. For ephemeral processes
(< 100ms lifetime), we'll often miss the window — that's acceptable.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import sys
import time
from typing import Optional

if sys.platform != "darwin":
    raise ImportError("Process enricher is macOS-only")

from agent import metrics

logger = logging.getLogger(__name__)

# sysctl constants
CTL_KERN = 1
KERN_PROCARGS2 = 49

# Load libc
_libc_path = ctypes.util.find_library("c")
if _libc_path:
    _libc = ctypes.CDLL(_libc_path)
else:
    _libc = None

# Prometheus metrics for enrichment tracking
try:
    from prometheus_client import Counter, Histogram

    cmdline_enrichment_total = Counter(
        "edr_cmdline_enrichment_total",
        "Total command line enrichment attempts",
        ["result"],
    )
    cmdline_enrichment_latency = Histogram(
        "edr_cmdline_enrichment_latency_seconds",
        "Time to enrich a single process command line",
        buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01),
    )
except Exception:
    cmdline_enrichment_total = None
    cmdline_enrichment_latency = None


def get_process_cmdline(pid: int) -> str | None:
    """Read full command line for a PID via sysctl KERN_PROCARGS2.

    Returns the full command line string, or None if the process
    has exited or we lack permission.
    """
    if _libc is None:
        return None

    t0 = time.monotonic()
    result_label = "success"

    try:
        # Buffer size query
        size = ctypes.c_size_t(0)
        mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)

        # First call to get buffer size
        if _libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            result_label = "failed_exited"
            return None

        if size.value == 0:
            result_label = "failed_exited"
            return None

        # Allocate buffer and read
        buf = ctypes.create_string_buffer(size.value)
        if _libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
            result_label = "failed_exited"
            return None

        # Parse: first 4 bytes = argc, then executable path (null-terminated),
        # then padding nulls, then argv strings (null-separated)
        raw = buf.raw[: size.value]
        if len(raw) < 4:
            result_label = "failed_exited"
            return None

        argc = int.from_bytes(raw[:4], byteorder="little")

        # Skip argc and executable path
        rest = raw[4:]
        try:
            exe_end = rest.index(b"\x00")
        except ValueError:
            result_label = "failed_exited"
            return None
        rest = rest[exe_end + 1 :]

        # Skip padding nulls
        while rest and rest[0:1] == b"\x00":
            rest = rest[1:]

        # Extract argc arguments
        args = []
        for _ in range(argc):
            if not rest:
                break
            try:
                end = rest.index(b"\x00")
            except ValueError:
                end = len(rest)
            args.append(rest[:end].decode("utf-8", errors="replace"))
            rest = rest[end + 1 :]

        if args:
            return " ".join(args)
        result_label = "failed_exited"
        return None

    except PermissionError:
        result_label = "failed_permission"
        return None
    except Exception:
        result_label = "failed_exited"
        return None
    finally:
        elapsed = time.monotonic() - t0
        if cmdline_enrichment_total is not None:
            cmdline_enrichment_total.labels(result=result_label).inc()
        if cmdline_enrichment_latency is not None:
            cmdline_enrichment_latency.observe(elapsed)


def enrich_process_event(raw_data: dict) -> dict:
    """Enrich a raw event dict with full command line if possible.

    Called from the processor thread for process events with incomplete
    command lines. Modifies the dict in-place and returns it.

    Args:
        raw_data: The deserialized RawEvent dict from the queue.

    Returns:
        The same dict, potentially with updated command_line field.
    """
    fields = raw_data.get("fields", {})
    source = raw_data.get("source", "")

    # Only enrich process events from unified_log
    if source not in ("unified_log", "macos_log", "psutil_process"):
        return raw_data

    pid_str = fields.get("pid", "")
    if not pid_str:
        return raw_data

    try:
        pid = int(pid_str)
    except (ValueError, TypeError):
        return raw_data

    if pid <= 0:
        return raw_data

    # Check if command line is already complete (has spaces = has args)
    existing_cmd = fields.get("command_line", "") or fields.get("cmd_line", "")
    if existing_cmd and " " in existing_cmd:
        # Already has arguments, skip enrichment
        return raw_data

    # Attempt enrichment
    cmdline = get_process_cmdline(pid)
    if cmdline:
        fields["command_line"] = cmdline
        fields["cmd_line"] = cmdline
        logger.debug("Enriched PID %d command line: %s", pid, cmdline[:100])

    return raw_data
