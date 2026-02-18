# Phase 7: macOS Production Hardening

## Context

The agent runs on macOS with 3 known gaps from live testing (commit 445bc8e):

1. **No file I/O events** — Endpoint Security framework requires Apple entitlement. No file create/modify/delete tracking.
2. **No persistence detection via file events** — LaunchAgent writes aren't captured, so the persistence detector never fires.
3. **Incomplete process command lines** — unified_log doesn't include full command arguments for most processes. Ephemeral process content can't be verified.

All three are solvable without Endpoint Security. This phase adds three macOS-specific collectors and integrates them into the existing pipeline.

**Implementation order matters. Follow the commit sequence below.**

---

## Commit 1: FSEvents File I/O Collector

### Create `agent/collectors/macos_fsevents_collector.py`

Use the `fsevents` Python package (PyPI: `fsevents`) to monitor filesystem changes. FSEvents is the macOS-native filesystem notification API — it's what Spotlight and Time Machine use. No entitlement required.

#### Installation

```bash
pip install fsevents
```

`fsevents` only works on macOS. Guard the import:

```python
import sys
if sys.platform != "darwin":
    raise ImportError("FSEvents collector is macOS-only")

import fsevents
```

#### What FSEvents Provides

- File/directory: created, modified, deleted, renamed
- The full path of the changed item
- Event flags indicating the type of change
- **Does NOT provide:** the PID that made the change (that requires Endpoint Security)

#### Implementation

- Watch these paths by default (configurable via `config.yaml`):

```yaml
collector:
  fsevents:
    watched_paths:
      - "/Users/"
      - "/tmp/"
      - "/var/tmp/"
      - "/etc/"
      - "/Library/LaunchAgents/"
      - "/Library/LaunchDaemons/"
      - "/Applications/"
    excluded_paths:
      - "/Users/*/Library/Caches/"
      - "/Users/*/Library/Logs/"
      - "/Users/*/.Trash/"
      - "/tmp/com.apple.*"
    latency: 0.5  # seconds — FSEvents coalescing interval
```

- For each FSEvents callback, create an `AgentEvent` with:
  - `event_type`: map FSEvents flags to `"file_create"`, `"file_modify"`, `"file_delete"`, `"file_rename"`
  - `file_path`: the full path from the event
  - `file_operation`: same as event_type without the `file_` prefix
  - `pid`: `None` (FSEvents doesn't provide this)
  - `timestamp`: current UTC time (FSEvents doesn't give precise timestamps per event)
  - `source`: `"fsevents"`

- **PID correlation heuristic:** Since FSEvents doesn't tell us which process made the change, implement a best-effort correlator:
  1. When a file event arrives, check the graph for processes that were running at that timestamp.
  2. If only one process has the file's directory in its `command_line` or `cwd`, attribute it.
  3. If multiple candidates exist or none match, create the File node with a `MODIFIED_BY_UNKNOWN` edge to a sentinel `(:Process {name: "unknown", pid: -1})` node.
  4. This is imperfect. That's fine. Log it at DEBUG level and move on.

- **Volume filtering:** FSEvents is noisy. Filter out:
  - Events in excluded_paths (glob matching)
  - `.DS_Store` files
  - Files with extensions: `.log`, `.tmp`, `.cache` (configurable)
  - Rapid duplicate events for the same path within 1 second (FSEvents can fire multiple callbacks for a single write)

- Run the FSEvents observer on its own thread. Push events into the shared event queue.

#### Integration

- Register this collector in `agent/collectors/__init__.py` for the macOS platform.
- The existing graph processor already handles `file_create`, `file_modify`, `file_delete` event types from Phase 2 — these FSEvents events should flow through the same path and create File nodes with edges.
- The persistence detector from Phase 2 (commit 4, `persistence_detector.py`) should now fire when FSEvents reports writes to `~/Library/LaunchAgents/`, `/Library/LaunchDaemons/`, etc.

#### Tests

- Test that FSEvents callback correctly maps flags to `AgentEvent.event_type`.
- Test path exclusion filtering (`.DS_Store`, cache dirs, `.log` files).
- Test deduplication of rapid duplicate events for the same path.
- Test that events with `pid=None` create File nodes with the unknown process sentinel edge.
- Test that writes to LaunchAgents paths trigger the persistence detector.

---

## Commit 2: LaunchAgent/Daemon Directory Polling (Belt and Suspenders)

### Create `agent/collectors/macos_persistence_poller.py`

FSEvents should catch LaunchAgent writes, but as a backup, implement a polling-based persistence monitor that snapshots LaunchAgent/LaunchDaemon directories and diffs them.

This is the "belt and suspenders" approach — if FSEvents misses something (which can happen if the coalescing window swallows a rapid create+modify), the poller catches it.

#### Implementation

- On startup, snapshot these directories:

```python
PERSISTENCE_DIRS = [
    os.path.expanduser("~/Library/LaunchAgents/"),
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    "/Library/StartupItems/",
]
```

- For each directory, record: `{filename: (mtime, sha256, size)}`.
- Every `poll_interval` seconds (default: 10, configurable), re-scan and diff:
  - **New file:** Emit a `file_create` AgentEvent for the path. Also parse the plist and extract `Label`, `ProgramArguments`, and `RunAtLoad` — include these in `AgentEvent.raw`.
  - **Modified file (mtime or hash changed):** Emit a `file_modify` AgentEvent. Include old and new hash in `raw`.
  - **Deleted file:** Emit a `file_delete` AgentEvent.
- Deduplicate against FSEvents: if the FSEvents collector already emitted an event for this path within the last `poll_interval`, skip it. Use a shared set (thread-safe) of recently-seen paths.

#### Plist Parsing

When a new or modified `.plist` file is detected, parse it and add structured data to `AgentEvent.raw`:

```python
import plistlib

def parse_launch_plist(path: str) -> Optional[dict]:
    try:
        with open(path, "rb") as f:
            plist = plistlib.load(f)
        return {
            "label": plist.get("Label"),
            "program": plist.get("Program"),
            "program_arguments": plist.get("ProgramArguments"),
            "run_at_load": plist.get("RunAtLoad", False),
            "keep_alive": plist.get("KeepAlive", False),
            "watch_paths": plist.get("WatchPaths"),
            "start_interval": plist.get("StartInterval"),
        }
    except Exception:
        return None
```

This structured plist data is extremely valuable for the LLM — it can reason about what the LaunchAgent actually does rather than just knowing a file was created.

#### Config

```yaml
collector:
  persistence_poller:
    enabled: true
    poll_interval_seconds: 10
    directories:
      - "~/Library/LaunchAgents/"
      - "/Library/LaunchAgents/"
      - "/Library/LaunchDaemons/"
      - "/Library/StartupItems/"
```

#### Tests

- Test that a new plist file in a watched directory triggers a `file_create` event.
- Test that modifying a plist triggers `file_modify` with old/new hash in raw.
- Test that deleting a plist triggers `file_delete`.
- Test plist parsing extracts Label, ProgramArguments, RunAtLoad correctly.
- Test deduplication: if FSEvents already reported the same path, poller skips it.
- Test that a malformed plist (binary garbage) doesn't crash the poller.

---

## Commit 3: Process Command Line Enrichment

### Create `agent/collectors/macos_proc_enricher.py`

The unified log gives us PIDs but not full command lines. This module enriches process events with command line arguments by querying the kernel via `sysctl`.

#### Implementation

Use `sysctl` with `CTL_KERN` + `KERN_PROCARGS2` via ctypes to read command line arguments for a given PID:

```python
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"))

CTL_KERN = 1
KERN_PROCARGS2 = 49

def get_process_cmdline(pid: int) -> Optional[str]:
    """Read full command line for a PID via sysctl KERN_PROCARGS2.
    
    Returns the full command line string, or None if the process
    has exited or we lack permission.
    """
    # Buffer size query
    size = ctypes.c_size_t(0)
    mib = (ctypes.c_int * 3)(CTL_KERN, KERN_PROCARGS2, pid)
    
    # First call to get buffer size
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
        return None
    
    # Allocate buffer and read
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None
    
    # Parse: first 4 bytes = argc, then executable path (null-terminated),
    # then padding nulls, then argv strings (null-separated)
    raw = buf.raw[:size.value]
    argc = int.from_bytes(raw[:4], byteorder="little")
    
    # Skip argc and executable path
    rest = raw[4:]
    exe_end = rest.index(b'\x00')
    rest = rest[exe_end + 1:]
    
    # Skip padding nulls
    while rest and rest[0:1] == b'\x00':
        rest = rest[1:]
    
    # Extract argc arguments
    args = []
    for _ in range(argc):
        if not rest:
            break
        end = rest.index(b'\x00') if b'\x00' in rest else len(rest)
        args.append(rest[:end].decode("utf-8", errors="replace"))
        rest = rest[end + 1:]
    
    return " ".join(args) if args else None
```

#### Integration as an Enrichment Step

This is NOT a standalone collector. It's an enrichment pass that runs in the graph processor:

1. When a `process_start` event arrives from the unified log collector with `command_line` as `None` or incomplete (just the binary name):
2. Immediately call `get_process_cmdline(event.pid)`.
3. If successful, update `event.command_line` with the full command line.
4. If the process has already exited (sysctl returns error), log at DEBUG and continue with whatever we have.

**Timing is critical.** The enrichment must happen as quickly as possible after the event arrives, before the process exits. For ephemeral processes (< 100ms lifetime), we'll often miss the window — that's acceptable. Log the miss rate as a metric.

#### Race Condition Handling

- `get_process_cmdline` will fail for processes that have already exited. This is expected and common for ephemeral processes.
- It will also fail for processes owned by other users if we're not running as root. When running as a LaunchDaemon (root), this isn't an issue.
- Never block the event pipeline waiting for enrichment. If sysctl takes > 10ms (shouldn't happen, it's a kernel call), skip and continue.

#### Metrics

- Add counter: `cmdline_enrichment_total` (labeled: `success`, `failed_exited`, `failed_permission`, `failed_timeout`)
- Add histogram: `cmdline_enrichment_latency_seconds`

#### Config

```yaml
collector:
  proc_enrichment:
    enabled: true
    timeout_ms: 10  # Max time to spend on sysctl call per PID
```

#### Tests

- Test that `get_process_cmdline(os.getpid())` returns the current process's command line.
- Test that `get_process_cmdline(99999999)` returns None (non-existent PID).
- Test that the enrichment step updates `event.command_line` when successful.
- Test that a failed enrichment doesn't block or crash the pipeline.
- Test that the metric counters increment correctly for success and failure cases.

---

## Commit 4: Integration and Collector Registration

### Update `agent/collectors/__init__.py`

On macOS, the full collector stack should now be:

```python
# macOS collector initialization order:
# 1. UnifiedLogCollector — process events, some network events
# 2. MacOSDnsCollector — DNS queries via tcpdump (added in 445bc8e)
# 3. PsutilCollector — network connections (supplement)
# 4. MacOSFSEventsCollector — file I/O events (NEW)
# 5. MacOSPersistencePoller — LaunchAgent/Daemon directory monitoring (NEW)
# 6. MacOSProcEnricher — command line enrichment pass (NEW, not a collector — runs in processor)
```

All collectors run concurrently, feeding into the shared event queue. The proc enricher runs in the graph processor, not as a separate collector.

### Update Config Defaults

Add the new macOS sections to `config.yaml` and the config model:

```yaml
collector:
  fsevents:
    watched_paths:
      - "/Users/"
      - "/tmp/"
      - "/var/tmp/"
      - "/etc/"
      - "/Library/LaunchAgents/"
      - "/Library/LaunchDaemons/"
      - "/Applications/"
    excluded_paths:
      - "/Users/*/Library/Caches/"
      - "/Users/*/Library/Logs/"
      - "/Users/*/.Trash/"
      - "/tmp/com.apple.*"
    excluded_extensions:
      - ".log"
      - ".tmp"
      - ".cache"
      - ".DS_Store"
    latency: 0.5
  persistence_poller:
    enabled: true
    poll_interval_seconds: 10
    directories:
      - "~/Library/LaunchAgents/"
      - "/Library/LaunchAgents/"
      - "/Library/LaunchDaemons/"
      - "/Library/StartupItems/"
  proc_enrichment:
    enabled: true
    timeout_ms: 10
```

### Update Live Test Simulations

Update `tests/live/attack_simulations.py`:

- **Test 3 (File Modification):** Should now produce File nodes on macOS via FSEvents. Update expected output.
- **Test 4 (Persistence):** LaunchAgent plist creation should now be detected by BOTH FSEvents and the persistence poller. Update expected output to confirm persistence detection fires with ATT&CK ID T1543.001.
- **Test 6 (Encoded Command):** With proc enrichment, the base64 encoded command line should now be captured for processes that live long enough. Update expected output.
- **Test 7 (Ephemeral Processes):** Some of the 20 ephemeral processes should now have command lines enriched. Don't expect 100% — log the enrichment success rate.

### Update `tests/live/validate.py`

Add macOS-specific validation checks:

```python
# New macOS checks:
{
    "name": "FSEvents file tracking active",
    "query": "Check for File nodes with source=fsevents",
    "pass_condition": "At least 1 File node created via FSEvents",
},
{
    "name": "LaunchAgent persistence detected",
    "query": "Check findings for T1543.001",
    "pass_condition": "Persistence finding with ATT&CK ID T1543.001 exists",
},
{
    "name": "Command line enrichment working",
    "query": "Check Process nodes for non-null command_line",
    "pass_condition": "At least 50% of Process nodes have command_line populated",
},
{
    "name": "Plist parsing in persistence events",
    "query": "Check raw data on persistence file events",
    "pass_condition": "At least 1 event has parsed plist data (Label, ProgramArguments)",
},
```

### Run Full Test Suite

After all 4 commits, run:
1. All 326 existing unit tests — must still pass.
2. New unit tests for FSEvents, persistence poller, and proc enricher.
3. Full live test suite on macOS: `run_live_tests.py` → `attack_simulations.py` (test 8, full kill chain) → `validate.py`.

---

## Cross-Cutting Requirements

### Error Handling
- FSEvents observer crash must not take down the agent. Wrap in try/except, log, increment `events_dropped_total`.
- Persistence poller encountering a directory it can't read (permission denied) should log a warning and skip that directory, not crash.
- `get_process_cmdline` failures are expected and frequent. Never log above DEBUG for individual failures — only log aggregate stats (enrichment success rate) at INFO on a periodic basis (every 60 seconds).

### Performance
- FSEvents latency of 0.5s means events are batched. This is fine — we're not doing real-time response on file events without PID attribution anyway.
- Persistence poller at 10s intervals is negligible CPU. Plist parsing is fast.
- `sysctl KERN_PROCARGS2` is a kernel call — should complete in < 1ms. The 10ms timeout is a safety net.
- FSEvents volume filtering is critical. Without it, `/Users/*/Library/Caches/` alone can generate hundreds of events per second during normal browsing.

### Dependencies
- `fsevents` (PyPI) — macOS only, C extension. Add to requirements with platform marker: `fsevents>=0.3; sys_platform == 'darwin'`
- `plistlib` — stdlib, no additional dependency.
- `ctypes` — stdlib, no additional dependency.`
