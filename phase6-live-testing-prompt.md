# Phase 6: Live Testing & Validation

## Context

All 5 implementation phases are complete. 19 commits, 326 unit tests passing. The agent has:
- Kernel event collectors: ETW (Windows), Auditd (Linux), unified log (macOS), psutil fallback
- Expanded graph: User, Process, IP, Domain, File, RegistryKey nodes
- DGA detection heuristic + persistence detection with MITRE ATT&CK mapping
- Response engine: suspend, terminate, network isolation, file quarantine, approval workflow, audit trail
- Self-protection: watchdog, tamper detection, Windows Service / systemd daemon
- Config system with YAML + CLI overrides
- Prometheus metrics + health endpoint

Now we need to validate it works on real hosts. The operator has a MacBook Pro (native macOS) and can spin up a Windows VM. All testing starts in LOG_ONLY / observation mode — no auto-respond.

---

## Step 1: Pre-Flight Checks

Before touching any VM, verify the agent can start cleanly on each platform.

### 1A: Create a test runner script

**Create `tests/live/run_live_tests.py`.**

This is NOT a unit test. It's a script that:
1. Starts the agent in the foreground with `--no-watchdog --no-tamper-check --log-format text --config config.yaml`
2. Waits 10 seconds for initialization
3. Hits the `/health` endpoint and verifies `{"status": "healthy"}`
4. Hits the `/metrics` endpoint and verifies Prometheus output is parseable
5. Prints a summary: collector type detected, events/second, queue depth, any errors in log output
6. Shuts down cleanly on Ctrl+C

### 1B: Create a safe test config

**Create `tests/live/test_config.yaml`.**

```yaml
agent:
  name: "edr-graph-test"
  version: "2.0.0"
  log_level: "DEBUG"
  log_format: "text"

collector:
  mode: "auto"
  buffer_size: 10000
  file_read_tracking: false

analysis:
  llm:
    provider: "deepinfra"
    api_key_env: "DEEPINFRA_API_KEY"
    max_tokens: 2048
    temperature: 0.1
    timeout_seconds: 30
    max_concurrent_calls: 1      # Conservative for testing
    rate_limit_per_minute: 10    # Conservative for testing
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
      - "apple.com"
      - "icloud.com"

response:
  auto_respond: false            # LOG_ONLY mode — observe, don't act
  auto_terminate: false

persistence:
  watchdog_enabled: false        # Disabled for testing
  heartbeat_interval_seconds: 10
  tamper_check_interval_seconds: 60

metrics:
  enabled: true
  port: 9100
```

---

## Step 2: Simulated Attack Scenarios

Create a test harness that generates known-malicious patterns the agent should detect. These are SAFE simulations — no actual malware.

### Create `tests/live/attack_simulations.py`

This script runs a menu-driven set of simulations. The operator picks which ones to run. Each simulation prints what it's about to do, waits for confirmation, executes, then tells the operator what the agent should have detected.

**IMPORTANT:** All simulations must be safe and reversible. No actual exploitation. We're testing telemetry and detection, not breaking things.

```
=== EDR Agent Live Test Suite ===

Select a test to run:

  [1] Process Chain Test
  [2] Suspicious DNS Resolution
  [3] File Modification (FIM) Test
  [4] Persistence Mechanism Test (platform-specific)
  [5] Network Connection Test
  [6] Encoded Command Test
  [7] Rapid Process Spawning (Ephemeral Execution)
  [8] Full Kill Chain Simulation
  [0] Run All Tests Sequentially
  [q] Quit

>>>
```

#### Test 1: Process Chain Test

**Purpose:** Verify the agent captures parent-child process relationships.

```python
# Spawn a chain: python -> sh/cmd -> whoami
# Expected: Agent sees 3-level process chain with correct PPIDs
```

- **macOS/Linux:** `subprocess.Popen(["sh", "-c", "whoami && id && uname -a"])`
- **Windows:** `subprocess.Popen(["cmd", "/c", "whoami & hostname & ipconfig"])`
- **Expected detection:** Process chain in graph. `build_attack_chain()` should show the full lineage.
- **Print:** "Agent should show: python (PID X) -> sh/cmd (PID Y) -> whoami (PID Z)"

#### Test 2: Suspicious DNS Resolution

**Purpose:** Verify DNS event capture and DGA detection.

```python
import socket

# Resolve known-good domains
socket.getaddrinfo("google.com", 80)
socket.getaddrinfo("github.com", 443)

# Resolve DGA-like domains (these are non-existent, resolution will fail — that's fine)
# The agent should still see the DNS query attempt
try:
    socket.getaddrinfo("xjk82mfq3p9a2z.xyz", 80)
except socket.gaierror:
    pass

try:
    socket.getaddrinfo("a8f3kq9xm2p7b4.top", 80)
except socket.gaierror:
    pass

# Resolve a domain with high entropy that actually exists (for resolution chain testing)
socket.getaddrinfo("neverssl.com", 80)
```

- **Expected detection:** Domain nodes created. DGA candidates flagged with score > 0.6. `risk_indicators` populated.
- **Print:** "Agent should show: Domain 'xjk82mfq3p9a2z.xyz' flagged as DGA candidate. Domain 'google.com' should NOT be flagged."

#### Test 3: File Modification (FIM) Test

**Purpose:** Verify file creation/modification events and File nodes in graph.

```python
import tempfile, os, time

test_dir = tempfile.mkdtemp(prefix="edr_test_")

# Create a file
test_file = os.path.join(test_dir, "test_payload.txt")
with open(test_file, "w") as f:
    f.write("initial content")

time.sleep(2)

# Modify the file
with open(test_file, "a") as f:
    f.write("\nmodified content - simulating data staging")

time.sleep(2)

# Create a suspicious file extension
suspicious_file = os.path.join(test_dir, "backdoor.php")
with open(suspicious_file, "w") as f:
    f.write("<?php echo 'test'; ?>")

time.sleep(2)

# Cleanup
os.remove(test_file)
os.remove(suspicious_file)
os.rmdir(test_dir)
```

- **Expected detection:** File nodes created with paths. CREATED and MODIFIED edges from the python process. SHA256 hashes computed (if files existed at processing time).
- **Print:** "Agent should show: File 'test_payload.txt' CREATED then MODIFIED. File 'backdoor.php' CREATED."

#### Test 4: Persistence Mechanism Test

**Purpose:** Verify persistence detection fires on known ATT&CK paths. Platform-specific.

##### macOS

```python
import tempfile, os, plistlib

# Create a fake LaunchAgent plist (in a temp location first, then copy)
plist_data = {
    "Label": "com.edr.test.fake",
    "ProgramArguments": ["/usr/bin/true"],
    "RunAtLoad": True,
}

# Write to user LaunchAgents directory
launch_agent_path = os.path.expanduser("~/Library/LaunchAgents/com.edr.test.fake.plist")
with open(launch_agent_path, "wb") as f:
    plistlib.dump(plist_data, f)

print(f"Created test LaunchAgent at: {launch_agent_path}")
print("Agent should detect: Persistence (T1543.001 - Launch Agent)")

time.sleep(5)

# Cleanup
os.remove(launch_agent_path)
print("Cleaned up test LaunchAgent.")
```

##### Windows

```python
import winreg, time

# Write a harmless test value to the current user's Run key
key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
value_name = "EDRGraphTest"
value_data = r"C:\Windows\System32\cmd.exe /c echo test"

try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
    winreg.CloseKey(key)
    print(f"Created test Run key: HKCU\\{key_path}\\{value_name}")
    print("Agent should detect: Persistence (T1547.001 - Registry Run Key)")

    time.sleep(5)

    # Cleanup
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
    winreg.DeleteValue(key, value_name)
    winreg.CloseKey(key)
    print("Cleaned up test Run key.")
except PermissionError:
    print("ERROR: Need to run as Administrator to write Run keys.")
```

##### Linux

```python
import tempfile, os, stat

# Create a fake cron job
cron_file = "/tmp/edr_test_cron"  # Write to /tmp first for safety
with open(cron_file, "w") as f:
    f.write("* * * * * /usr/bin/true\n")
print(f"Created test cron file at: {cron_file}")

# If running as root (in a test VM), copy to actual cron location
if os.geteuid() == 0:
    import shutil
    actual_cron = "/etc/cron.d/edr_test_fake"
    shutil.copy(cron_file, actual_cron)
    print(f"Copied to {actual_cron}")
    print("Agent should detect: Persistence (T1053.003 - Cron)")
    time.sleep(5)
    os.remove(actual_cron)
    print("Cleaned up.")
else:
    print("Not running as root — agent may not detect /tmp writes as persistence.")
    print("For full test, run simulation as root in the test VM.")

os.remove(cron_file)
```

- **Expected detection:** PersistenceResult with correct ATT&CK technique ID and HIGH severity.

#### Test 5: Network Connection Test

**Purpose:** Verify outbound connection tracking and IP node creation.

```python
import socket, time

# Connect to known-good services
targets = [
    ("1.1.1.1", 80, "Cloudflare DNS HTTP"),
    ("8.8.8.8", 53, "Google DNS"),
    ("93.184.216.34", 80, "example.com"),
]

for ip, port, desc in targets:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        print(f"Connected to {ip}:{port} ({desc})")
        sock.close()
    except Exception as e:
        print(f"Failed to connect to {ip}:{port}: {e}")
    time.sleep(1)
```

- **Expected detection:** IP nodes created with addresses and ports. CONNECTED_TO edges from the python process.

#### Test 6: Encoded Command Test

**Purpose:** Verify the agent captures suspicious command line arguments that the LLM should flag.

##### macOS/Linux

```python
import subprocess, base64

# Base64 encoded "whoami" — classic attacker technique
encoded = base64.b64encode(b"whoami").decode()
subprocess.run(["sh", "-c", f"echo {encoded} | base64 -d | sh"], capture_output=True)
```

##### Windows

```python
import subprocess, base64

# PowerShell encoded command (UTF-16LE base64 of "whoami")
cmd = "whoami"
encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
subprocess.run(["powershell", "-EncodedCommand", encoded], capture_output=True)
```

- **Expected detection:** Process with suspicious command line (`-EncodedCommand`, `base64 -d | sh`). LLM should flag this.

#### Test 7: Rapid Process Spawning

**Purpose:** Verify the agent captures ephemeral processes that exist for < 1 second. This is the key improvement over psutil polling.

```python
import subprocess, time

print("Spawning 20 short-lived processes in rapid succession...")
start = time.time()

for i in range(20):
    # Each process lives for ~50ms
    if sys.platform == "win32":
        subprocess.run(["cmd", "/c", f"echo ephemeral_{i}"], capture_output=True)
    else:
        subprocess.run(["sh", "-c", f"echo ephemeral_{i}"], capture_output=True)

elapsed = time.time() - start
print(f"Spawned 20 processes in {elapsed:.2f}s")
print(f"Agent should have captured all 20 process_start events.")
print(f"Check metrics: events_processed_total should have increased by >= 20")
```

- **Expected detection:** All 20 processes captured with correct image names and command lines. This is the test that proves ETW/auditd is working — psutil polling would miss most of these.

#### Test 8: Full Kill Chain Simulation

**Purpose:** Simulate a realistic attack sequence and verify the agent builds a complete attack chain.

```python
"""
Simulated kill chain:
1. Initial access: Encoded command execution (simulating macro/exploit)
2. Discovery: whoami, ipconfig/ifconfig, net user/id
3. Persistence: Write to Run key (Windows) or LaunchAgent (macOS)
4. C2: DNS resolution of DGA-like domain
5. Staging: Write payload to temp file
6. Exfiltration: Outbound connection

All actions are safe — no actual exploitation.
"""

import subprocess, socket, os, sys, time, base64, tempfile

print("=== Full Kill Chain Simulation ===")
print("This runs all attack stages sequentially.\n")

# Stage 1: Initial access via encoded command
print("[Stage 1] Encoded command execution...")
if sys.platform == "win32":
    encoded = base64.b64encode("whoami".encode("utf-16-le")).decode()
    subprocess.run(["powershell", "-EncodedCommand", encoded], capture_output=True)
else:
    encoded = base64.b64encode(b"whoami").decode()
    subprocess.run(["sh", "-c", f"echo {encoded} | base64 -d | sh"], capture_output=True)
time.sleep(2)

# Stage 2: Discovery
print("[Stage 2] System discovery...")
if sys.platform == "win32":
    subprocess.run(["cmd", "/c", "whoami & hostname & ipconfig & net user"], capture_output=True)
else:
    subprocess.run(["sh", "-c", "whoami && hostname && ifconfig && id"], capture_output=True)
time.sleep(2)

# Stage 3: Persistence
print("[Stage 3] Persistence mechanism...")
if sys.platform == "darwin":
    import plistlib
    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.edr.killchain.test.plist")
    plist_data = {"Label": "com.edr.killchain.test", "ProgramArguments": ["/usr/bin/true"], "RunAtLoad": True}
    with open(plist_path, "wb") as f:
        plistlib.dump(plist_data, f)
    persistence_cleanup = lambda: os.remove(plist_path)
elif sys.platform == "win32":
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "EDRKillChainTest", 0, winreg.REG_SZ, r"C:\Windows\System32\cmd.exe /c echo test")
    winreg.CloseKey(key)
    def persistence_cleanup():
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "EDRKillChainTest")
        winreg.CloseKey(key)
else:
    persistence_cleanup = lambda: None
    print("  (Skipping persistence on Linux — would need root for /etc/cron.d)")
time.sleep(2)

# Stage 4: C2 beacon (DGA-like DNS)
print("[Stage 4] C2 DNS beacon...")
dga_domains = ["xjk82mfq3p9a2z.xyz", "q7w2m9f4p8k1.top", "b3x7n2k9m5p1.net"]
for domain in dga_domains:
    try:
        socket.getaddrinfo(domain, 443)
    except socket.gaierror:
        pass
    time.sleep(0.5)
time.sleep(2)

# Stage 5: Staging
print("[Stage 5] Data staging...")
staging_dir = tempfile.mkdtemp(prefix="edr_staging_")
staged_file = os.path.join(staging_dir, "exfil_data.enc")
with open(staged_file, "w") as f:
    f.write("SIMULATED_SENSITIVE_DATA_" * 100)
time.sleep(2)

# Stage 6: Exfiltration attempt
print("[Stage 6] Exfiltration connection...")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(("93.184.216.34", 443))  # example.com
    sock.close()
except Exception:
    pass
time.sleep(2)

# Cleanup
print("\n[Cleanup] Removing artifacts...")
persistence_cleanup()
os.remove(staged_file)
os.rmdir(staging_dir)

print("\n=== Kill Chain Complete ===")
print("Expected agent detections:")
print("  1. Encoded command execution (suspicious command line)")
print("  2. Discovery commands (whoami, ipconfig/ifconfig)")
print("  3. Persistence mechanism (T1547.001 or T1543.001)")
print("  4. DGA domain resolution (3 candidates, score > 0.6)")
print("  5. File staging (CREATED edge to temp file)")
print("  6. Outbound connection (CONNECTED_TO edge)")
print("  7. Full attack chain should link all 6 stages through process tree")
print("\nCheck: build_attack_chain() for the python PID should show all of the above.")
```

---

## Step 3: Metrics Validation Script

### Create `tests/live/check_metrics.py`

A script that polls the Prometheus metrics endpoint and prints a human-readable dashboard:

```
=== EDR Agent Metrics Dashboard ===
Uptime: 342s
Events processed: 1,247
Events dropped: 0
Event rate: 3.6 events/sec
Queue depth: 12

Processing latency (p50/p95/p99): 2.1ms / 8.4ms / 15.2ms
LLM call latency (p50/p95/p99): 420ms / 890ms / 1200ms

LLM verdicts: INFO=1180  LOW=42  MEDIUM=18  HIGH=5  CRITICAL=2
DGA detections: 3
Persistence detections: 1
Response actions: 0 (auto_respond=false)

Attack chain build latency (p50/p95): 1.2ms / 4.8ms
```

- Poll `/metrics` every 5 seconds.
- Parse Prometheus text format.
- Calculate rates from counter deltas between polls.
- Highlight any concerning values in red (events_dropped > 0, queue_depth > buffer_size * 0.8).

---

## Step 4: Validation Checklist Script

### Create `tests/live/validate.py`

After running the simulations, this script queries the agent's graph database and audit trail to verify detections actually occurred.

```python
"""
Post-simulation validation. Run this AFTER running attack_simulations.py.

Queries the agent's graph DB and prints pass/fail for each expected detection.
"""

# For each test, query the graph and verify:

checks = [
    {
        "name": "Process chain captured",
        "query": "Check for Process nodes with SPAWNED edges at least 2 levels deep",
        "pass_condition": "At least one 3-level process chain exists",
    },
    {
        "name": "DGA domain detected",
        "query": "Check Domain nodes where is_dga_candidate = True",
        "pass_condition": "At least 2 DGA candidate domains exist",
    },
    {
        "name": "Legitimate domain NOT flagged",
        "query": "Check Domain node for google.com",
        "pass_condition": "is_dga_candidate = False",
    },
    {
        "name": "File creation tracked",
        "query": "Check for File nodes with CREATED edges",
        "pass_condition": "At least 1 File node with CREATED edge exists",
    },
    {
        "name": "Persistence detected",
        "query": "Check risk_indicators for any T1547 or T1543 technique IDs",
        "pass_condition": "At least 1 persistence detection in audit log",
    },
    {
        "name": "Network connection tracked",
        "query": "Check IP nodes with CONNECTED_TO edges",
        "pass_condition": "At least 1 IP node with connection from test process",
    },
    {
        "name": "Ephemeral processes captured",
        "query": "Check for Process nodes matching 'echo ephemeral_*'",
        "pass_condition": "At least 15 of 20 ephemeral processes captured",
    },
    {
        "name": "Attack chain builds successfully",
        "query": "Call build_attack_chain() for the simulation PID",
        "pass_condition": "Returns dict with non-empty process_chain, network_footprint, and risk_indicators",
    },
    {
        "name": "Metrics endpoint healthy",
        "query": "GET http://localhost:9100/health",
        "pass_condition": "Returns status=healthy with events_last_minute > 0",
    },
    {
        "name": "No dropped events",
        "query": "Check events_dropped_total metric",
        "pass_condition": "events_dropped_total == 0",
    },
]
```

For each check, print:
```
[PASS] Process chain captured — Found 4 chains, deepest is 3 levels
[PASS] DGA domain detected — 3 DGA candidates found (scores: 0.82, 0.79, 0.71)
[PASS] Legitimate domain NOT flagged — google.com is_dga_candidate=False
[FAIL] Ephemeral processes captured — Only 12 of 20 captured (60%)
       ↳ This may indicate the collector is not keeping up. Check buffer_size.
```

---

## Implementation Notes

- All test scripts go in `tests/live/` — keep them separate from unit tests.
- Every simulation cleans up after itself. No persistent artifacts left on the test system.
- The validation script should import from the agent's own modules to query the graph — don't reimplement graph queries.
- Print clear, actionable output. The operator is reading terminal output, not a dashboard.
- Handle platform differences with `sys.platform` checks throughout. macOS, Windows, and Linux paths all need to work.
- If a simulation requires elevated privileges (e.g., writing to system cron on Linux, Run keys on Windows), print a clear message and skip gracefully rather than crashing.
