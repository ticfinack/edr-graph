# Phase 2: Graph Schema Expansion & Detection Heuristics

## Context

Phases 0 and 1 are complete. The agent now has:
- Structured logging (structlog, JSON/text formats)
- Prometheus metrics on port 9100 with health endpoint
- Pipeline instrumentation (processing latency, event counters, LLM latency/verdicts)
- Platform collectors: ETW (Windows), Auditd (Linux), enhanced unified log (macOS), psutil fallback
- 70 passing tests across 8 commits

Phase 2 expands the graph data model with new node types and adds lightweight detection heuristics that run before LLM analysis. This improves the LLM's reasoning by giving it richer attack chain context and reduces unnecessary LLM calls by pre-filtering with cheap heuristics.

**Implementation order matters. Follow the commit sequence below exactly.**

---

## Commit 1: Graph Schema Expansion (2A)

### New Node Types

Add these node types to the graph schema alongside the existing User, Process, and IP nodes:

```
(:Domain {
    name: str,              # "evil.example.com"
    first_seen: datetime,
    last_seen: datetime,
    is_dga_candidate: bool, # Set by DGA detector in a later commit
    tld: str,               # "com"
})

(:File {
    path: str,              # Full normalized path
    hash_sha256: Optional[str],  # Computed on first observation if file exists
    size: Optional[int],
    first_seen: datetime,
    last_seen: datetime,
})

(:RegistryKey {
    path: str,              # Full registry path
    value_name: Optional[str],
    value_data: Optional[str],
    previous_data: Optional[str],  # Captured on modification events
    first_seen: datetime,
    last_seen: datetime,
})
```

### New Edge Types

```
(:Process)-[:RESOLVED]->(:Domain)       # DNS query
(:Domain)-[:RESOLVES_TO]->(:IP)         # DNS response mapping
(:Process)-[:CREATED]->(:File)          # File creation
(:Process)-[:MODIFIED]->(:File)         # File write/modify
(:Process)-[:READ]->(:File)             # File read (optional, high volume — gate behind config flag)
(:Process)-[:DELETED]->(:File)          # File deletion
(:Process)-[:CREATED]->(:RegistryKey)   # Registry key/value creation (Windows only)
(:Process)-[:MODIFIED]->(:RegistryKey)  # Registry value change (Windows only)
(:Process)-[:DELETED]->(:RegistryKey)   # Registry key/value deletion (Windows only)
```

### Implementation Details

- Update `agent/graph/schema.py` (or wherever node/edge types are defined) with the new types.
- Update `agent/graph/processor.py` to handle incoming `AgentEvent` objects with `event_type` of `dns_resolve`, `file_create`, `file_modify`, `file_delete`, `registry_create`, `registry_modify`, `registry_delete` and create the appropriate nodes and edges.
- For DNS events: create both the Domain node and the Domain→IP edge if `resolved_ips` is populated on the event.
- For File events: attempt SHA256 hash computation only if the file still exists at processing time. Don't block on it — if the file is gone (deleted/moved), store `hash_sha256 = None`.
- For RegistryKey nodes: capture `previous_data` by reading the current value before processing a modify event (Windows only, via `winreg`). If the read fails, set `previous_data = None`.
- File READ edges are high-volume. Gate them behind a config flag `collector.file_read_tracking: false` (default off). Everything else is always on.

### Config Addition

Add to `config.yaml` under `collector`:

```yaml
collector:
  file_read_tracking: false  # Enable (:Process)-[:READ]->(:File) edges. High volume.
```

### Tests

- Test that a `dns_resolve` AgentEvent creates Domain node, IP node (if new), and correct edges.
- Test that a `file_modify` AgentEvent creates File node with hash when file exists, and without hash when file doesn't exist.
- Test that a `registry_modify` AgentEvent creates RegistryKey node with `previous_data` populated.
- Test that duplicate Domain/File/RegistryKey nodes are deduplicated (upserted, not duplicated).
- Test that `file_read_tracking: false` suppresses READ edge creation.

---

## Commit 2: Graph Query Helpers (2D)

### Create `agent/graph/queries.py`

Implement these reusable graph traversal functions. Each should work against whatever graph backend is in use (NetworkX, dict-based, etc.):

```python
def get_process_chain(graph, pid: int) -> List[dict]:
    """Walk SPAWNED edges upward to build the full parent process chain.
    Returns list from root ancestor down to the given PID.
    Example: [systemd, bash, python, malware.py]"""

def get_process_network_footprint(graph, pid: int) -> dict:
    """All network activity for a process.
    Returns: {
        "domains": [{"name": ..., "first_seen": ..., "is_dga_candidate": ...}],
        "ips": [{"address": ..., "port": ..., "protocol": ...}],
        "dns_chains": [{"domain": ..., "resolved_to": [...]}]
    }"""

def get_domain_resolution_history(graph, domain_name: str) -> List[dict]:
    """All IPs a domain has resolved to over time.
    Returns: [{"ip": ..., "first_seen": ..., "last_seen": ...}]"""

def get_file_activity(graph, file_path: str) -> List[dict]:
    """All processes that touched a file and how.
    Returns: [{"pid": ..., "process_name": ..., "operation": "CREATED"|"MODIFIED"|"DELETED", "timestamp": ...}]"""

def get_persistence_artifacts(graph, pid: int) -> List[dict]:
    """All registry persistence created by a process or its child tree.
    Walks the process tree downward and collects all RegistryKey nodes.
    Returns: [{"registry_path": ..., "value_name": ..., "value_data": ..., "created_by_pid": ...}]"""

def build_attack_chain(graph, pid: int) -> dict:
    """Comprehensive context object for LLM consumption.
    Combines all of the above into a single structured dict:
    {
        "target_process": {"pid": ..., "name": ..., "command_line": ..., "user": ...},
        "process_chain": [...],          # from get_process_chain
        "network_footprint": {...},       # from get_process_network_footprint
        "file_activity": [...],           # files touched by this process
        "persistence_artifacts": [...],   # from get_persistence_artifacts
        "risk_indicators": [...]          # populated by detectors in later commits
    }
    """
```

### LLM Context Integration

Update `agent/analysis/llm_analyzer.py` to call `build_attack_chain(pid)` instead of whatever minimal context it currently sends. The attack chain dict should be serialized to a concise string for the LLM prompt. Keep it under 2000 tokens — summarize if the chain is too large (truncate file activity to top 10 most recent, etc.).

### Tests

- Test `get_process_chain` with a 3-level deep process tree.
- Test `get_process_network_footprint` with a process that has both DNS and direct IP connections.
- Test `build_attack_chain` produces a complete dict with all sections populated.
- Test that `build_attack_chain` handles a process with zero network/file/registry activity gracefully (empty lists, not errors).
- Test LLM context serialization stays under 2000 tokens for a moderately complex chain.

---

## Commit 3: DGA Detection Heuristic (2B)

### Create `agent/analysis/dga_detector.py`

A lightweight, synchronous detector that scores domain names for DGA characteristics. This runs on every DNS event **before** any LLM call.

#### Scoring Algorithm

Compute a composite score from these signals:

1. **Shannon entropy** of the domain name (excluding TLD): Higher entropy = more random.
   - Typical legitimate domain entropy: 2.0–3.0
   - Typical DGA domain entropy: 3.5+

2. **Consonant-to-vowel ratio**: DGA domains tend to have unusual letter distributions.
   - Normal English: ~0.6 vowels per character
   - DGA: often < 0.3 or highly irregular

3. **Domain length**: Longer random strings are more suspicious.
   - Flag domains > 15 characters in the second-level domain.

4. **Bigram frequency**: Compare character bigrams against English language frequency.
   - Use a pre-computed bigram frequency table (embed as a dict constant, not a file).
   - Low average bigram frequency = likely random/generated.

5. **Numeric ratio**: High percentage of digits in the domain name.

#### Interface

```python
@dataclass
class DGAResult:
    domain: str
    score: float          # 0.0 (definitely legit) to 1.0 (definitely DGA)
    entropy: float
    consonant_vowel_ratio: float
    bigram_score: float
    is_dga_candidate: bool  # True if score > threshold
    reasons: List[str]      # Human-readable explanations: ["High entropy: 4.2", "Low bigram freq"]

def analyze_domain(domain: str, threshold: float = 0.6) -> DGAResult:
    """Score a domain name for DGA characteristics."""
```

#### Integration

- In the graph processor, when a DNS event creates a Domain node, immediately run `analyze_domain()` and set `is_dga_candidate` on the node.
- If `is_dga_candidate is True`, add `"DGA candidate (score: X.XX)"` to the `risk_indicators` list in `build_attack_chain()`.
- The DGA score should be included in the LLM context so the LLM can factor it into its analysis.
- Log DGA detections at WARNING level with the domain name and score.

#### Allowlist

Add a config option for known-good domains that should skip DGA analysis:

```yaml
analysis:
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
```

#### Tests

- Test that `google.com` scores low (< 0.3).
- Test that a known DGA-style domain like `xjk82mfq3p.xyz` scores high (> 0.6).
- Test that allowlisted domains always return `is_dga_candidate = False` regardless of score.
- Test that the DGA result is correctly attached to the Domain node in the graph.
- Test edge case: single-character domains, punycode domains, IP-literal domains (should not crash).

---

## Commit 4: Persistence Detection (2C)

### Create `agent/analysis/persistence_detector.py`

A rule-based detector that monitors registry and filesystem paths commonly abused for persistence. This is platform-aware.

#### Windows Registry Persistence Paths

Monitor writes to these registry paths. Any write to these paths automatically sets severity to HIGH in `risk_indicators`:

```python
WINDOWS_PERSISTENCE_KEYS = {
    # Run keys
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    # Services
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    # Winlogon
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    # Context menu handlers (COM hijack vector)
    r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
    r"HKLM\SOFTWARE\Classes\CLSID",
    # WMI persistence
    r"HKLM\SOFTWARE\Microsoft\WBEM\ESS",
    # Scheduled tasks
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
    # AppInit DLLs (DLL injection)
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    # Image File Execution Options (debugger hijack)
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
}
```

Use **prefix matching** — a write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyMalware` matches the `Run` key.

#### macOS Persistence Paths

Monitor file creation/modification in:

```python
MACOS_PERSISTENCE_PATHS = {
    "~/Library/LaunchAgents/",          # User-level launch agents
    "/Library/LaunchAgents/",           # System-wide launch agents
    "/Library/LaunchDaemons/",          # System-wide launch daemons
    "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/",
    "/Library/StartupItems/",           # Legacy startup items
    "/etc/periodic/",                   # Periodic scripts
    "~/Library/Preferences/",           # Login items via plist manipulation
}
```

#### Linux Persistence Paths

Monitor file creation/modification in:

```python
LINUX_PERSISTENCE_PATHS = {
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",                 # User crontabs
    "/etc/systemd/system/",             # systemd unit files
    "/usr/lib/systemd/system/",
    "~/.config/systemd/user/",          # User-level systemd units
    "/etc/init.d/",                     # SysV init scripts
    "/etc/rc.local",
    "~/.bashrc",                        # Shell profile persistence
    "~/.bash_profile",
    "~/.profile",
    "/etc/ld.so.preload",              # Shared library injection
}
```

#### Interface

```python
@dataclass
class PersistenceResult:
    path: str                    # The registry key or file path that was written
    persistence_type: str        # "registry_run_key", "launch_agent", "cron_job", "systemd_unit", etc.
    platform: str                # "windows", "macos", "linux"
    severity: str                # Always "HIGH" for known persistence paths
    mitre_technique: str         # ATT&CK ID: "T1547.001", "T1543.001", etc.
    description: str             # Human-readable: "Process X wrote to Windows Run key"

def check_persistence(event: AgentEvent) -> Optional[PersistenceResult]:
    """Check if an event represents a persistence mechanism installation.
    Returns None if the event is not persistence-related."""
```

#### MITRE ATT&CK Mapping

Map each persistence type to its ATT&CK technique ID:

| Persistence Type | ATT&CK ID | Name |
|---|---|---|
| Windows Run keys | T1547.001 | Boot/Logon Autostart: Registry Run Keys |
| Windows Services | T1543.003 | Create or Modify System Process: Windows Service |
| Scheduled Tasks | T1053.005 | Scheduled Task |
| WMI Event Sub | T1546.003 | Event Triggered Execution: WMI |
| AppInit DLLs | T1546.010 | Event Triggered Execution: AppInit DLLs |
| IFEO Debugger | T1546.012 | Event Triggered Execution: IFEO |
| macOS LaunchAgent | T1543.001 | Create or Modify System Process: Launch Agent |
| macOS LaunchDaemon | T1543.004 | Create or Modify System Process: Launch Daemon |
| Linux cron | T1053.003 | Scheduled Task: Cron |
| Linux systemd | T1543.002 | Create or Modify System Process: Systemd Service |
| Shell profile | T1546.004 | Event Triggered Execution: Unix Shell Config |
| ld.so.preload | T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking |

#### Integration

- In the graph processor, run `check_persistence()` on every `file_create`, `file_modify`, `registry_create`, and `registry_modify` event.
- If a PersistenceResult is returned, add it to the `risk_indicators` list in `build_attack_chain()`.
- Include the ATT&CK technique ID in the LLM context — this helps the LLM map to known attack patterns.
- Log persistence detections at WARNING level.

#### Tests

- Test that writing to `HKLM\...\Run\malware` triggers detection with correct ATT&CK ID.
- Test that writing to `/etc/cron.d/backdoor` triggers detection on Linux.
- Test that writing to `~/Library/LaunchAgents/evil.plist` triggers detection on macOS.
- Test that writing to a non-persistence path (e.g., `/tmp/notes.txt`) returns None.
- Test prefix matching: `HKLM\...\Run\anything` matches the `Run` key pattern.
- Test that `build_attack_chain` includes persistence results in `risk_indicators`.

---

## Cross-Cutting Requirements

### Error Handling
- No new node type or detector should be able to crash the event processing pipeline. Wrap all new processing in try/except, log errors, increment `events_dropped_total`, and continue.
- Hash computation failure (permission denied, file gone) should log a warning and continue with `hash_sha256 = None`.
- Registry read failure for `previous_data` should not block event processing.

### Performance
- DGA analysis must complete in < 1ms per domain. It's pure math, no I/O.
- Persistence detection must complete in < 0.1ms per event. It's string prefix matching.
- File hashing (SHA256) should be async or at minimum non-blocking on the main processing thread. For large files (> 100MB), skip hashing and log a warning.

### Metrics
- Add a new counter: `dga_detections_total`
- Add a new counter: `persistence_detections_total` (labeled by `persistence_type`)
- Add a histogram: `attack_chain_build_latency_seconds`

### Backward Compatibility
- Existing tests must continue to pass. Events that don't produce Domain/File/RegistryKey nodes should work exactly as before.
- The graph processor must handle events from both old collectors (that don't emit DNS/file/registry events) and new collectors seamlessly.
