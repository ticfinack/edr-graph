# System Limitations

A transparent assessment of eDR-Graph's constraints, tradeoffs, and known gaps. Understanding these limitations is essential for deploying the agent appropriately and setting realistic expectations.

---

## LLM Hallucination Risk

The LLM threat analyzer can produce false positives — flagging legitimate behavior as malicious — or false negatives — missing genuine threats.

**Mitigations in place:**

- **Graph ground truth** — The response engine verifies LLM findings against the actual Kuzu graph before executing actions. If the LLM claims a process chain that doesn't exist in the graph, the response is vetoed.
- **Allowlist override** — Response Engine allowlist rules can override LLM verdicts for known-good behaviors.
- **Protected process list** — System-critical processes (`launchd`, `csrss.exe`, `systemd`, `sshd`, etc.) cannot be terminated regardless of LLM severity.
- **Human approval gate** — In Active mode without `auto_respond`, destructive actions require human approval via the dashboard.

**Residual risk:** In Active mode with `auto_respond: true`, a hallucinated CRITICAL finding can trigger automated enforcement (suspend/terminate/isolate) without human review. This mode should only be used with well-tuned allowlists and a mature behavioral baseline.

---

## LLM Latency

The LLM analyzer runs on a 60-second interval (`analyzer_interval` setting). Combined with API round-trip time (2-30 seconds depending on load), novel threats have a worst-case detection latency of ~90 seconds.

**Why this is acceptable:** The fast-path blocklist handles all known threats in sub-millisecond time. The LLM is only invoked for genuinely novel behaviors that pass through the novelty filter. Known C2 IPs, malicious domains, and prohibited process chains are blocked instantly without waiting for the LLM.

**When this matters:** A truly novel attack — one that doesn't match any IOC feed, blocklist rule, or known pattern — will not be detected until the next analyzer cycle.

---

## API Dependency

The LLM analyzer requires an external API (DeepInfra) for threat analysis. If the API is unavailable (network outage, rate limiting, key expiry), the LLM pipeline pauses.

**Fail-open design:** The agent degrades gracefully:

- The fast-path blocklist remains active (in-memory, no API dependency)
- IOC feed matching continues (cached locally)
- DGA detection continues (local analysis)
- Persistence detection continues (local monitoring)
- Graph writes and event processing continue normally

Only the LLM analysis and tool-use investigation pause until API connectivity is restored.

---

## Graph Database Constraints

**No secondary indexes:** Kuzu 0.11.x only indexes the primary key (`id STRING`) via hash index. There is no `CREATE INDEX` syntax for secondary columns. This means queries filtering on non-primary-key fields (e.g., `WHERE pid = $pid`) require full table scans.

**Workaround:** An in-memory PID index (`agent/graph/pid_index.py`) maps `pid → node_ids` and `ppid → child_pids`. It's built at startup (~8 seconds for 500K+ nodes) and updated on each upsert. All dashboard graph queries use this index for O(1) PID lookups.

**Single-writer constraint:** Kuzu supports only one concurrent writer. All graph writes are serialized through a single `graph-writer` thread via an MPSC queue. This prevents write conflicts but introduces serialization latency under heavy write loads.

**Buffer pool sizing:** The Kuzu buffer pool is capped at 128-256 MB (auto-calculated). Kuzu's query processing uses ~3x the buffer pool, so total Kuzu memory is typically 384-768 MB.

---

## Memory Footprint

| Component | Typical Usage |
|-----------|--------------|
| Kuzu graph database | 384-768 MB (3x buffer pool) |
| PID index | 50-200 MB (depends on node count) |
| SQLite queue + findings | 10-50 MB |
| IOC feeds (in-memory) | 20-40 MB (~50K indicators) |
| Python runtime + agent code | 50-100 MB |
| **Total** | **1-2 GB typical** |

On a 4 GB host, Kuzu alone consumes ~768 MB. The total agent footprint of 1-2 GB leaves limited headroom for the host's primary workload.

**Resource requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 2 GB | 4 GB+ |
| Disk | 500 MB | 2 GB+ (graph growth depends on TTL and event volume) |
| CPU | 1 core | 2+ cores (separate core for graph writer) |
| Python | 3.11+ | 3.13 |

---

## Tamper Protection Gaps

eDR-Graph runs as a **user-space process**. A root-level attacker can:

- Kill the agent process (`kill -9`)
- Modify agent source files on disk
- Alter the SQLite database or Kuzu graph directly
- Disable the systemd service or LaunchDaemon

**Mitigations:**

- SHA-256 tamper detection checks all agent source files every 60 seconds
- Watchdog heartbeat allows external monitoring to detect agent failure
- Protected process list prevents the agent from being killed by its own response engine

**What's missing:** No kernel-level self-protection. Enterprise EDR solutions (CrowdStrike, SentinelOne) use ring-0 kernel drivers that survive root compromise. eDR-Graph cannot achieve this level of tamper resistance as a user-space Python application.

**Tamper check window:** The 60-second tamper check interval means an attacker has up to 60 seconds to modify agent files before detection.

---

## macOS ESF Limitation

The Endpoint Security Framework (ESF) would provide kernel-level process, file, and network events on macOS. However, ESF requires an Apple-issued `com.apple.developer.endpoint-security.client` entitlement, only available to approved signed binaries distributed through Apple's developer program.

An ESF stub exists in the codebase but is **inactive**. All macOS detection relies on:

- Unified Log polling (1-5 second latency)
- FSEvents (no PID attribution)
- psutil process polling
- tcpdump DNS/connection capture

This means macOS detection is inherently **post-execution** — the agent sees events after they occur, not as they happen.

---

## Network Isolation Race Conditions

**macOS:** pf (packet filter) does not support per-PID network rules. The agent uses `lsof` to discover a process's active connections, then installs pf rules for those specific IP:port pairs. There is a time gap between:

1. The lsof lookup (discovers current connections)
2. The pf rule installation (blocks those connections)

During this gap, the process can establish new connections to different IPs that won't be blocked until the next isolation attempt.

**Linux:** iptables with `--pid-owner` (`xt_owner` module) provides true per-PID network isolation with no race condition. However, the `xt_owner` kernel module must be loaded.

---

## Forensic Gaps

**FSEvents (macOS):** File system events do not include PID attribution. The agent knows that `/tmp/malware.sh` was created, but cannot directly determine which process created it. Attribution requires correlating timestamps and shared entities across the graph.

**Cross-process correlation:** When one process writes a file and another process reads it, the graph contains separate `CREATED_FILE` and `READ_FILE` edges. Linking these as a single attack chain requires LLM reasoning over the graph — there is no automatic file-based process correlation.

**Short-lived processes:** Processes that execute and exit within the collector polling interval (1 second default) may be missed by psutil-based collection. eBPF (Linux) catches these via kernel tracepoints. On macOS and Windows, short-lived processes are captured if they appear in the Unified Log or ETW stream.

---

## Scale Constraints

eDR-Graph is designed for **single-endpoint deployment**. It is not a fleet management solution on its own:

- No central management console (fleet mode forwards findings to a central server, but orchestration is external)
- Graph database is local and embedded (no distributed queries across endpoints)
- PID index is built in-memory at startup, taking ~8 seconds per 500K nodes
- Graph reaper runs hourly with a 24-hour TTL default — high-volume endpoints may need more aggressive pruning
