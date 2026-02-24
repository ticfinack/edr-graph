# OS Capabilities & Response Times

eDR-Graph runs on Linux, macOS, and Windows with platform-native telemetry sources and response mechanisms. This page documents the capabilities, response times, and platform-specific considerations.

---

## Platform Telemetry Matrix

=== "Linux"

    | Capability | Source | Notes |
    |------------|--------|-------|
    | **Process events** | eBPF (`execve` tracepoint) + auditd + psutil | eBPF preferred; psutil snapshot-only when eBPF active |
    | **Network connections** | eBPF (`connect` tracepoint) + auditd + psutil | Kernel-level syscall interception |
    | **DNS queries** | Via network events | No dedicated DNS collector |
    | **File I/O** | auditd (file watches) | Configurable audit rules |
    | **Registry** | N/A | — |
    | **Authentication** | syslog (auth.log) + auditd | PAM, SSH, su/sudo events |
    | **Command line args** | auditd / /proc | Full argument capture |
    | **Container awareness** | cgroup v2 detection | Process-to-container attribution |

    **Requirements:** Root or `CAP_AUDIT_READ` for auditd; root + BCC + kernel headers for eBPF; `xt_owner` kernel module for per-PID network isolation.

=== "macOS"

    | Capability | Source | Notes |
    |------------|--------|-------|
    | **Process events** | Unified Log + psutil | Log stream parsing + polling |
    | **Network connections** | Unified Log + psutil | Connection metadata via tcpdump SYN |
    | **DNS queries** | tcpdump (port 53) | Dedicated DNS collector |
    | **File I/O** | FSEvents | **No PID attribution** (see limitations) |
    | **Registry** | N/A | — |
    | **Authentication** | Unified Log (authd, securityd) | Local + SSH auth events |
    | **TLS fingerprinting** | tcpdump (ClientHello) | JA3/JA3S fingerprinting |
    | **Command line args** | sysctl KERN_PROCARGS2 | Via macOS proc enricher |

    **Requirements:** Root for tcpdump and pf packet filter rules.

=== "Windows"

    | Capability | Source | Notes |
    |------------|--------|-------|
    | **Process events** | ETW Kernel-Process + Sysmon + psutil | Richest telemetry of all platforms |
    | **Network connections** | ETW Kernel-Network + Sysmon + psutil | Kernel-level network events |
    | **DNS queries** | ETW DNS-Client | Dedicated ETW provider |
    | **File I/O** | ETW Kernel-File | Full file operation tracking |
    | **Registry** | ETW Kernel-Registry | Create, modify, delete operations |
    | **Authentication** | Event Log Security | Logon, logoff, account events |
    | **Command line args** | Sysmon / ETW | Full argument capture |

    **Requirements:** pywin32 for Windows Service integration; Administrator for ETW.

---

## Response Action Matrix

| Action | macOS | Linux | Windows |
|--------|-------|-------|---------|
| **Process suspend/resume** | SIGSTOP / SIGCONT | SIGSTOP / SIGCONT | NtSuspendProcess / NtResumeProcess (ctypes) |
| **Process terminate** | SIGKILL | SIGKILL | TerminateProcess (ctypes) |
| **Network isolation** | pf anchor rules (per-IP via lsof) | iptables `--pid-owner` (xt_owner) | netsh advfirewall (per-program) |
| **Connection blocking** | pf anchor rules | iptables destination match | netsh remoteip rules |
| **DNS sinkhole** | /etc/hosts + `killall -HUP mDNSResponder` | /etc/hosts + `systemd-resolve --flush-caches` | /etc/hosts |
| **Panic mode** | pf block-all except lo0 | iptables block-all except lo | netsh block-all except loopback |

---

## MTTD (Mean Time to Detect)

| Capability | Linux (eBPF) | Linux (auditd) | macOS | Windows (ETW) |
|------------|-------------|----------------|-------|---------------|
| Process execution | < 1 ms | ~10 ms | 1-5 s (log polling) | < 1 ms |
| Network connection | < 1 ms | ~10 ms | 1-5 s (log polling) | < 1 ms |
| File modification | ~10 ms (auditd) | ~10 ms | ~1 s (FSEvents) | < 1 ms |
| DNS query | ~10 ms | ~10 ms | ~100 ms (tcpdump) | < 1 ms |
| Registry modification | N/A | N/A | N/A | < 1 ms |
| Known IOC (IP/domain/hash) | < 1 ms | < 1 ms | < 1 ms | < 1 ms |
| Novel threat (LLM) | ~60 s | ~60 s | ~60 s | ~60 s |

---

## MTTR (Mean Time to Respond)

| Action | Linux | macOS | Windows |
|--------|-------|-------|---------|
| Fast-path block (SIGKILL) | < 5 ms | < 5 ms | < 10 ms |
| Network isolation (per-PID) | < 50 ms | < 100 ms (lsof→pf) | < 50 ms |
| DNS sinkhole | < 100 ms | < 500 ms (mDNSResponder flush) | < 100 ms |
| Connection block (specific IP) | < 50 ms | < 100 ms | < 50 ms |
| File quarantine | < 100 ms | < 100 ms | < 100 ms |
| LLM-driven response | 2-30 s | 2-30 s | 2-30 s |

---

## Kinetic Impact: MTTD & MTTR Comparison

| Defense Layer | MTTD | MTTR | Attacker's Reality |
|---|---|---|---|
| Industry Average (Legacy SIEM/EDR) | ~10-14 Days | Hours to Days | Persistence, rootkits, lateral movement before SOC alert |
| eDR-Graph Stage 3 (LLM) | ~2-5 Seconds | Minutes | Shell obtained but quarantined before exfil |
| eDR-Graph Stage 2 (Fast-Path) | < 100 Microseconds | < 5 Milliseconds | Attack fails — SIGKILL before shell initializes |

The dual-pipeline architecture means known threats never reach the LLM. The fast-path blocklist evaluates IPs, domains, CIDRs, process names, file paths, and chain patterns using O(1) compiled in-memory structures. When a match is found, the response engine fires immediately — the process is killed before it can complete initialization.

---

## Linux eBPF: Kernel-Level Enforcement

When eBPF is available (root + BCC + kernel headers), eDR-Graph gains kernel-level telemetry:

- **Syscall interception** — `execve` and `connect` tracepoints fire before the syscall completes
- **Process visibility** — Full process creation context including UID, parent PID, command line
- **Network visibility** — Connection attempts captured at the kernel level, before the socket opens
- **Zero-copy performance** — Events are delivered to user-space via ring buffers with minimal overhead

Combined with the fast-path blocklist, this enables enforcement before the target process can execute its first instruction or establish its first network connection.

When eBPF is not available, the agent falls back to psutil polling (process/network) and auditd (syscall tracing), which provide equivalent coverage with slightly higher latency.

---

## macOS Considerations

!!! warning "Endpoint Security Framework (ESF)"
    macOS offers the Endpoint Security Framework for kernel-level process/file/network events. However, ESF requires an Apple-issued `com.apple.developer.endpoint-security.client` entitlement, only available to approved signed binaries. An ESF stub exists in the codebase but is **not active**. All macOS detection is post-execution via Unified Log polling and psutil.

**FSEvents limitation:** File events from FSEvents do **not** include PID attribution. The agent can detect that a file was created/modified/deleted, but cannot directly determine which process performed the operation. Cross-process correlation requires matching timestamps and shared entities in the graph.

**Unified Log polling latency:** The Unified Log is polled rather than streamed, introducing 1-5 second detection latency for process and network events. This means macOS detection is inherently post-execution — the process has already started by the time the agent sees it.

**Network isolation:** macOS pf (packet filter) does not support per-PID network blocking. The agent works around this by using `lsof` to discover a process's active connections and blocking those specific IP:port pairs via pf anchor rules. There is a small time gap between the lsof lookup and the pf rule installation.

---

## Windows Considerations

Windows ETW (Event Tracing for Windows) provides the richest telemetry of all three platforms:

- **Kernel-level callbacks** for process, network, file, DNS, and registry events
- **Sysmon integration** for enhanced process creation logging
- **Event Log** for security, authentication, and system events

**User-space delivery latency:** While ETW captures events at the kernel level, they are delivered to user-space consumers asynchronously. The delivery latency is typically < 1 ms but can spike under heavy system load.

**Process control:** Process suspend/resume uses undocumented `NtSuspendProcess`/`NtResumeProcess` via ctypes, providing forensic preservation of process state (memory, handles) before termination.

---

## Container Awareness (Linux Only)

On Linux with cgroup v2, the agent detects containerized processes and includes container context in the graph:

- Process-to-cgroup attribution
- Container-aware chain patterns
- Memory limit detection for dynamic buffer pool sizing

Container awareness requires cgroup v2 (default on modern Linux distributions).
