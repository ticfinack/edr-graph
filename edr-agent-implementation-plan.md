# Project Vigilance: EDR Agent Implementation Plan

## System Prompt / Project Context

You are implementing the evolution of `edr-graph`, a Python-based Host Intrusion Detection System (HIDS) with LLM-powered investigation, into a production-grade Endpoint Detection & Response (EDR) agent. The existing system uses `psutil` for process enumeration, SQLite for event queuing, a graph data model (User → Process → IP), and DeepInfra LLM calls for threat analysis.

This is a phased implementation. Complete each phase fully before moving to the next. After each phase, run all existing tests and confirm nothing regresses before proceeding.

---

## Phase 0: Instrumentation & Baseline Metrics

**Goal:** Before changing anything, instrument the current agent so we can measure improvements.

### Tasks

1. **Add structured logging throughout the existing codebase.**
   - Use Python's `logging` module with `structlog` for JSON-formatted output.
   - Every event processed should log: `event_type`, `timestamp`, `processing_latency_ms`, `source` (psutil/etw/auditd).
   - Log LLM call latency, token usage, and verdict separately.

2. **Create a metrics collection module (`agent/metrics.py`).**
   - Track and expose:
     - `events_processed_total` (counter)
     - `events_dropped_total` (counter, for when the queue overflows)
     - `event_processing_latency_seconds` (histogram)
     - `llm_call_latency_seconds` (histogram)
     - `llm_verdicts` (counter by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL)
     - `false_positive_rate` (tracked via manual feedback flag in SQLite)
     - `agent_uptime_seconds` (gauge)
   - Use `prometheus_client` library to expose a `/metrics` endpoint on a local port (default 9100) for scraping.

3. **Add a health check endpoint (`/health`)** on the same local port.
   - Returns JSON: `{"status": "healthy", "uptime": ..., "events_last_minute": ..., "queue_depth": ...}`

4. **Baseline test:** Run the instrumented agent for 10 minutes on a test host. Record average event processing latency and events/second throughput. Store these numbers in `docs/baseline_metrics.md`.

---

## Phase 1: Real-Time Kernel Event Subscriptions

**Goal:** Replace `psutil.process_iter()` polling with kernel-pushed event streams. This is the single most important upgrade.

### 1A: Windows — ETW (Event Tracing for Windows)

**Create `agent/collectors/etw_collector.py`.**

- Use the `pywintrace` library as primary. If it proves unreliable, fall back to calling Win32 ETW APIs via `ctypes`.
- Subscribe to the following ETW providers:

| Provider | GUID | Events |
|----------|------|--------|
| `Microsoft-Windows-Kernel-Process` | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | Process start/stop |
| `Microsoft-Windows-Kernel-Network` | `{7DD42A49-5329-4832-8DFD-43D979153A88}` | TCP/UDP connections |
| `Microsoft-Windows-DNS-Client` | `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` | DNS resolution |
| `Microsoft-Windows-Kernel-File` | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | File I/O |
| `Microsoft-Windows-Kernel-Registry` | `{70EB4F03-C1DE-4F73-A051-33D13D5413BD}` | Registry modifications |

- Each ETW event must be normalized into a standard `AgentEvent` dataclass:

```python
@dataclass
class AgentEvent:
    event_id: str           # UUID
    timestamp: datetime     # UTC
    event_type: str         # "process_start", "process_stop", "network_connect", "dns_resolve", "file_modify", "registry_modify"
    source: str             # "etw", "ebpf", "auditd", "psutil"
    pid: int
    ppid: Optional[int]
    image_name: Optional[str]
    command_line: Optional[str]
    user: Optional[str]
    # Network fields
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    protocol: Optional[str]
    # DNS fields
    query_name: Optional[str]
    resolved_ips: Optional[List[str]]
    # File fields
    file_path: Optional[str]
    file_operation: Optional[str]  # "create", "modify", "delete", "rename"
    # Registry fields
    registry_key: Optional[str]
    registry_value: Optional[str]
    registry_operation: Optional[str]  # "create", "modify", "delete"
    # Raw data for forensics
    raw: Optional[dict] = None
```

- The ETW consumer MUST run on its own dedicated thread. Events are pushed into an `asyncio.Queue` or `queue.Queue` (thread-safe) that feeds the existing processing pipeline.
- Implement a **ring buffer** (fixed-size deque or `collections.deque(maxlen=N)`) between the ETW consumer and the graph processor. If the processor falls behind, old events are dropped and `events_dropped_total` metric is incremented. Default buffer size: 10,000 events.
- Gracefully handle ETW session teardown on agent shutdown (call `StopTrace`).

### 1B: Linux — Auditd via Netlink (with eBPF upgrade path)

**Create `agent/collectors/auditd_collector.py`.**

- Use `audit` library or raw Netlink socket to consume auditd events.
- Configure audit rules on startup for:
  - `execve` syscalls (process execution)
  - `connect` syscalls (network connections)
  - File watches on critical paths (`/etc/`, `/tmp/`, `/var/www/`)
- Normalize all events into the same `AgentEvent` dataclass.
- Include a `TODO` block and interface stub for future eBPF collector (`agent/collectors/ebpf_collector.py`) that implements the same `Collector` protocol.

### 1C: Collector Protocol & Platform Abstraction

**Create `agent/collectors/base.py`.**

```python
from typing import Protocol, AsyncIterator

class Collector(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def events(self) -> AsyncIterator[AgentEvent]: ...
    def platform(self) -> str: ...  # "windows", "linux"
```

**Create `agent/collectors/__init__.py`** with a factory:

```python
def get_collector() -> Collector:
    if sys.platform == "win32":
        return ETWCollector()
    elif sys.platform == "linux":
        return AuditdCollector()
    else:
        raise UnsupportedPlatformError(f"No collector for {sys.platform}")
```

### 1D: Retain psutil as Fallback

- Do NOT delete the existing psutil polling code. Wrap it as `PsutilCollector` implementing the same `Collector` protocol.
- If ETW/Auditd fails to initialize (missing permissions, unsupported OS version), fall back to psutil with a WARNING log.
- Add a config flag: `collector_mode: "auto" | "etw" | "auditd" | "psutil"`

### 1E: Testing

- Write unit tests that mock ETW events and verify they produce correct `AgentEvent` objects.
- Write an integration test that starts the ETW collector, spawns `calc.exe` (or `notepad.exe`), and asserts a `process_start` event is received within 1 second.
- Measure and log: events/second throughput and average latency from kernel event to `AgentEvent` creation. Compare against Phase 0 baseline.

---

## Phase 2: Expanded Graph Schema

**Goal:** Add Domain, File, and RegistryKey node types to the graph. This dramatically improves the LLM's ability to reason about attack chains.

### 2A: New Node Types

Extend the graph schema (whatever graph representation you're using — NetworkX, Neo4j, or custom) with these nodes and edges:

```
Existing:
  (:User {username, sid, domain})
  (:Process {pid, ppid, name, command_line, start_time, end_time})
  (:IP {address, port, protocol, geo_country, geo_city})

  (:User)-[:LAUNCHED]->(:Process)
  (:Process)-[:SPAWNED]->(:Process)
  (:Process)-[:CONNECTED_TO]->(:IP)

New:
  (:Domain {name, first_seen, last_seen, is_dga_candidate: bool})
  (:File {path, hash_sha256, size, last_modified})
  (:RegistryKey {path, value_name, value_data, previous_data})

  (:Process)-[:RESOLVED]->(:Domain)
  (:Domain)-[:RESOLVES_TO]->(:IP)
  (:Process)-[:MODIFIED]->(:File)
  (:Process)-[:READ]->(:File)
  (:Process)-[:CREATED]->(:File)
  (:Process)-[:DELETED]->(:File)
  (:Process)-[:MODIFIED]->(:RegistryKey)
  (:Process)-[:CREATED]->(:RegistryKey)
  (:Process)-[:DELETED]->(:RegistryKey)
```

### 2B: DGA Detection Heuristic

**Create `agent/analysis/dga_detector.py`.**

- Implement a lightweight DGA (Domain Generation Algorithm) detector that scores domain names.
- Use entropy calculation + consonant-to-vowel ratio + domain length.
- If `dga_score > threshold`, set `is_dga_candidate = True` on the Domain node.
- This runs synchronously — no LLM call needed. It's a pre-filter that flags suspicious domains for the LLM to investigate.

### 2C: Registry Persistence Detection

**Create `agent/analysis/persistence_detector.py`.**

- Monitor specific registry paths that are commonly abused for persistence:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SYSTEM\CurrentControlSet\Services`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
  - `HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers`
  - WMI event subscriptions: `HKLM\SOFTWARE\Microsoft\WBEM\ESS`
  - Scheduled tasks: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`
- Any write to these paths automatically escalates to HIGH severity before LLM analysis.

### 2D: Graph Query Helpers

**Create `agent/graph/queries.py`.**

Implement reusable graph traversal functions:

- `get_process_chain(pid) -> List[Process]` — Walk the SPAWNED edges to build the full parent chain.
- `get_process_network_footprint(pid) -> Dict` — All IPs and Domains a process has touched.
- `get_domain_resolution_history(domain) -> List[IP]` — All IPs a domain has resolved to.
- `get_file_modifiers(file_path) -> List[Process]` — All processes that touched a file.
- `get_persistence_artifacts(pid) -> List[RegistryKey]` — All registry persistence created by a process tree.
- `build_attack_chain(pid) -> Dict` — Comprehensive context object combining all of the above, formatted for LLM consumption.

The `build_attack_chain()` output is what gets sent to the LLM. It should produce a structured dict that can be serialized to a concise but complete context string.

---

## Phase 3: Response Engine

**Goal:** Add the ability to take automated response actions. This is the "R" in EDR.

### 3A: Response Action Framework

**Create `agent/response/actions.py`.**

Define a response action enum and execution framework:

```python
class ResponseAction(Enum):
    LOG_ONLY = "log_only"
    ALERT = "alert"
    SUSPEND_PROCESS = "suspend_process"
    TERMINATE_PROCESS = "terminate_process"
    ISOLATE_NETWORK = "isolate_network"
    QUARANTINE_FILE = "quarantine_file"

class ResponsePolicy:
    """Maps LLM severity verdicts to response actions."""
    
    SEVERITY_MAP = {
        "INFO": [ResponseAction.LOG_ONLY],
        "LOW": [ResponseAction.LOG_ONLY],
        "MEDIUM": [ResponseAction.ALERT],
        "HIGH": [ResponseAction.ALERT, ResponseAction.ISOLATE_NETWORK],
        "CRITICAL": [ResponseAction.ALERT, ResponseAction.SUSPEND_PROCESS, ResponseAction.ISOLATE_NETWORK],
    }
```

**CRITICAL: Implement a Do-Not-Kill list.**

```python
PROTECTED_PROCESSES = {
    # Windows critical processes — terminating these causes BSOD or system instability
    "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "System", "Registry", "Memory Compression",
    # Linux critical processes
    "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
    # The agent itself
    "edr-graph", "edr-watchdog",
}
```

### 3B: Process Suspension (Preferred over Termination)

**Create `agent/response/process_control.py`.**

- **Windows:** Use `NtSuspendProcess` via ctypes to freeze a process. This preserves forensic state (memory, handles, network connections) and is reversible if the verdict is a false positive.
- **Linux:** Send `SIGSTOP` to the process.
- Only escalate to `TerminateProcess` / `SIGKILL` if:
  1. LLM severity is CRITICAL, AND
  2. The process is NOT in the protected list, AND
  3. A configurable `auto_terminate` flag is True (default: False — requires manual confirmation).

### 3C: Network Isolation

**Create `agent/response/network_control.py`.**

- **Windows:** Use `netsh advfirewall` to add block rules for a specific process/PID.
  - Command: `netsh advfirewall firewall add rule name="EDR-BLOCK-{pid}" dir=out action=block program="{exe_path}"`
  - Also add inbound rule.
  - Track all rules added so they can be reverted: store rule names in SQLite.
- **Linux:** Use `iptables` with cgroup or owner matching.
- Implement `isolate(pid)` and `restore(pid)` methods.
- Network isolation is the preferred first response for HIGH severity — it stops data exfiltration while preserving the process for investigation.

### 3D: File Quarantine

**Create `agent/response/file_quarantine.py`.**

- Move suspicious files to a quarantine directory (`/var/edr-quarantine/` or `C:\ProgramData\edr-graph\quarantine\`).
- Rename with `.quarantined` extension and strip execute permissions.
- Log original path, SHA256 hash, and quarantine timestamp in SQLite.
- Implement `quarantine(file_path)` and `restore(file_path)` methods.

### 3E: Human-in-the-Loop Confirmation

**Create `agent/response/approval.py`.**

- For any destructive action (terminate, quarantine), queue an approval request.
- Approval can come via:
  1. Local CLI prompt (for single-host mode).
  2. Webhook to a central management server (for future multi-host deployment).
  3. Auto-approve if the policy flag `auto_respond` is set and severity is CRITICAL.
- Log all approvals and denials with timestamps and the approver identity.

### 3F: Response Audit Trail

- Every response action (including LOG_ONLY) must be recorded in SQLite with:
  - `response_id`, `event_id`, `timestamp`, `action_taken`, `target_pid`, `target_path`, `llm_severity`, `llm_confidence`, `approved_by`, `reverted`, `revert_timestamp`
- This is your forensic chain of custody. It must be tamper-evident — append-only, no updates or deletes.

---

## Phase 4: Self-Protection & Persistence

**Goal:** Make the agent resilient to being killed by users or malware.

### 4A: Windows Service

**Create `agent/platform/windows_service.py`.**

- Use `pywin32` to implement a Windows Service.
- Service name: `EDRGraphAgent`
- Runs as `SYSTEM`.
- Startup type: Automatic.
- Recovery options: Restart on first, second, and subsequent failures (1 second delay).
- Implement proper `SvcDoRun`, `SvcStop` handlers.

### 4B: Linux systemd Daemon

**Create deployment files:**

- `deploy/edr-graph.service` — systemd unit file.
  - `Restart=always`, `RestartSec=1`
  - `WatchdogSec=30` (systemd will kill and restart if the agent doesn't send heartbeats)
  - Run as a dedicated `edr-graph` user with appropriate capabilities (`CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_AUDIT_CONTROL`).

### 4C: Watchdog Process

**Create `agent/watchdog.py`.**

- A separate lightweight process that:
  1. Monitors the main agent process via PID and heartbeat file.
  2. Restarts the agent if it dies or stops heartbeating.
  3. The main agent also monitors the watchdog.
  4. Mutual monitoring: if either dies, the other restarts it.
- The watchdog should be as minimal as possible — no imports beyond stdlib. It should be hard to crash.
- Communication via a shared heartbeat file or local socket (not shared memory — that's fragile).

### 4D: Tamper Detection

**Create `agent/platform/tamper_detection.py`.**

- On startup, compute SHA256 of all agent binary/script files.
- Periodically (every 60 seconds) re-verify these hashes.
- If any agent files have been modified, log a CRITICAL alert and notify the central server (when available).
- Monitor the Windows Service registry key for unauthorized modifications.

---

## Phase 5: Configuration & Deployment

**Goal:** Make the agent configurable without code changes and deployable to new hosts.

### 5A: Configuration File

**Create `agent/config.py` and `config.yaml`.**

```yaml
agent:
  name: "edr-graph-agent"
  version: "2.0.0"
  log_level: "INFO"
  log_format: "json"  # "json" or "text"

collector:
  mode: "auto"  # "auto", "etw", "auditd", "psutil"
  buffer_size: 10000
  etw:
    providers:
      - "Microsoft-Windows-Kernel-Process"
      - "Microsoft-Windows-Kernel-Network"
      - "Microsoft-Windows-DNS-Client"
      - "Microsoft-Windows-Kernel-File"
      - "Microsoft-Windows-Kernel-Registry"
  auditd:
    watched_paths:
      - "/etc/"
      - "/tmp/"
      - "/var/www/"
      - "/home/"

analysis:
  llm:
    provider: "deepinfra"
    model: "meta-llama/Meta-Llama-3.1-70B-Instruct"
    api_key_env: "DEEPINFRA_API_KEY"  # Read from environment variable
    max_tokens: 2048
    temperature: 0.1
    timeout_seconds: 30
    max_concurrent_calls: 3
    rate_limit_per_minute: 30
  dga:
    entropy_threshold: 3.5
    min_domain_length: 12

response:
  auto_respond: false  # If true, CRITICAL severity auto-executes response
  auto_terminate: false  # If true, allows process termination without human approval
  quarantine_dir_windows: "C:\\ProgramData\\edr-graph\\quarantine"
  quarantine_dir_linux: "/var/edr-graph/quarantine"
  protected_processes:
    - "csrss.exe"
    - "smss.exe"
    - "wininit.exe"
    - "winlogon.exe"
    - "lsass.exe"
    - "services.exe"
    - "svchost.exe"
    - "dwm.exe"
    - "explorer.exe"
    - "System"
    - "systemd"
    - "init"

persistence:
  watchdog_enabled: true
  heartbeat_interval_seconds: 10
  tamper_check_interval_seconds: 60

metrics:
  enabled: true
  port: 9100
```

- Use `pydantic` for config validation with sensible defaults.
- Config is loaded from (in priority order): CLI args → environment variables → config file → defaults.

### 5B: Installation Script

**Create `deploy/install.sh` (Linux) and `deploy/install.ps1` (Windows).**

- Install Python dependencies from `requirements.txt`.
- Create the service user (Linux) or verify SYSTEM permissions (Windows).
- Install the service/daemon.
- Write initial config.
- Start the agent and verify it's running.

---

## Cross-Cutting Concerns (Apply Throughout All Phases)

### Error Handling

- **Never crash the agent on a single bad event.** Wrap all event processing in try/except. Log the error, increment `events_dropped_total`, and continue.
- LLM API failures should fall back to rule-based severity (e.g., if a process writes to a Run key, that's HIGH even without LLM confirmation).
- Network timeouts to the LLM should not block event processing. Use asyncio with timeouts.

### Security of the Agent Itself

- The LLM API key must NEVER be stored in the config file. Read from environment variable only.
- All local IPC (metrics endpoint, health check) should bind to `127.0.0.1` only.
- The SQLite database should have restrictive file permissions (owner-only read/write).
- Agent logs should not contain raw command lines in production mode — hash or truncate sensitive arguments.

### Testing Strategy

- **Unit tests:** Mock all OS APIs (ETW, auditd, process control). Test event normalization, graph construction, DGA detection, response policy mapping.
- **Integration tests:** Spin up the agent on a test VM, generate known-malicious patterns (e.g., `powershell -encodedCommand ...`, writing to Run keys), verify detection and response.
- **Regression tests:** After each phase, re-run all previous phase tests.

### Project Structure

```
edr-graph/
├── agent/
│   ├── __init__.py
│   ├── main.py                    # Entry point
│   ├── config.py                  # Pydantic config model
│   ├── metrics.py                 # Prometheus metrics
│   ├── models.py                  # AgentEvent dataclass + graph node models
│   ├── collectors/
│   │   ├── __init__.py            # Collector factory
│   │   ├── base.py                # Collector protocol
│   │   ├── etw_collector.py       # Windows ETW
│   │   ├── auditd_collector.py    # Linux Auditd
│   │   ├── ebpf_collector.py      # Future: eBPF
│   │   └── psutil_collector.py    # Fallback
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── schema.py              # Node/Edge type definitions
│   │   ├── processor.py           # Event → Graph updates
│   │   └── queries.py             # Graph traversal helpers
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── llm_analyzer.py        # DeepInfra LLM integration
│   │   ├── dga_detector.py        # Domain generation algorithm detection
│   │   ├── persistence_detector.py # Registry persistence rules
│   │   └── rule_engine.py         # Fallback rule-based detection
│   ├── response/
│   │   ├── __init__.py
│   │   ├── actions.py             # ResponseAction enum + policy
│   │   ├── process_control.py     # Suspend/terminate
│   │   ├── network_control.py     # Firewall rules
│   │   ├── file_quarantine.py     # File isolation
│   │   └── approval.py            # Human-in-the-loop
│   ├── platform/
│   │   ├── __init__.py
│   │   ├── windows_service.py     # pywin32 service wrapper
│   │   └── tamper_detection.py    # File integrity monitoring of agent itself
│   └── watchdog.py                # Mutual watchdog process
├── deploy/
│   ├── edr-graph.service          # systemd unit file
│   ├── install.sh                 # Linux installer
│   └── install.ps1                # Windows installer
├── config.yaml                    # Default configuration
├── requirements.txt
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
└── docs/
    ├── baseline_metrics.md
    ├── architecture.md
    └── response_playbook.md
```

---

## Implementation Order

Execute phases in this exact order. Do not skip ahead.

1. **Phase 0** — Instrumentation (1-2 days)
2. **Phase 1C** — Collector protocol and platform abstraction (half day)
3. **Phase 1D** — Wrap existing psutil as PsutilCollector (half day)
4. **Phase 1A** — ETW collector (2-3 days, this is the hardest part)
5. **Phase 1B** — Auditd collector (1-2 days)
6. **Phase 1E** — Testing and latency comparison (1 day)
7. **Phase 2A** — Graph schema expansion (1 day)
8. **Phase 2B** — DGA detector (half day)
9. **Phase 2C** — Registry persistence detector (half day)
10. **Phase 2D** — Graph query helpers + `build_attack_chain()` (1 day)
11. **Phase 3A-3D** — Response engine (2-3 days)
12. **Phase 3E-3F** — Approval workflow and audit trail (1 day)
13. **Phase 4** — Self-protection and persistence (2 days)
14. **Phase 5** — Configuration and deployment (1 day)

---

## Key Principles

- **Never crash.** The agent must survive any single bad event, failed API call, or unexpected input.
- **Prefer suspension over termination.** Forensic data is more valuable than a quick kill.
- **The LLM is an advisor, not an executor.** All destructive actions require policy + (optionally) human approval.
- **Measure everything.** If you can't measure whether a change improved detection, you can't justify it.
- **Degrade gracefully.** ETW fails? Fall back to psutil. LLM down? Fall back to rules. Network isolated? Queue events locally.
