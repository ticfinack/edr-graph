# Threat Landscape & Response

This document maps eDR-Graph's detection and response capabilities across MITRE ATT&CK phases, shell attack surfaces, and detection layers.

---

## Detection/Response by MITRE ATT&CK Phase

### Initial Access (TA0001)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| SSH brute force | Authentication event correlation, source IP reputation | Block IP, alert | Fast-path (ms) |
| Malicious download | IOC feed matching (URLhaus, ThreatFox) | Alert, quarantine file | Fast-path (ms) |
| Drive-by compromise | DNS DGA detection, domain reputation | DNS sinkhole, alert | Real-time (ms) |
| Phishing payload execution | Process ancestry anomaly (e.g., browser → shell) | Suspend/terminate, alert | LLM (seconds) |

### Execution (TA0002)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| Command-line interpreter abuse | Chain-aware blocklist (`** > curl > sh`) | SIGKILL | Fast-path (< 1ms) |
| LOLBin exploitation | LOLBAS database lookup + process hierarchy intelligence | Alert, suspend | LLM (seconds) |
| Script interpreter spawning | Parent-child relationship anomaly detection | Alert, context investigation | LLM (seconds) |
| Scheduled task/cron creation | Persistence detector (file/registry monitoring) | Alert, quarantine | Real-time (ms) |

### Persistence (TA0003)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| LaunchAgent/LaunchDaemon (macOS) | Persistence poller monitoring | Alert, quarantine plist | Real-time (ms) |
| Registry Run keys (Windows) | ETW registry monitoring + persistence detector | Alert, registry rollback | Real-time (ms) |
| Cron/systemd modification (Linux) | auditd file watches + persistence detector | Alert, quarantine | Real-time (ms) |
| Startup folder modification | File activity monitoring | Alert, quarantine | Real-time (ms) |

### Defense Evasion (TA0005)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| Process injection | Parent-child anomaly (unexpected ancestry) | Alert, investigate chain | LLM (seconds) |
| Masquerading | Code signing verification (macOS), exe path mismatch | Alert, terminate | LLM (seconds) |
| Indicator removal | Tamper detection (SHA-256 baseline monitoring) | Alert | 60s check interval |
| LOLBin proxy execution | LOLBAS lookup + graph chain context | Alert, suspend | LLM (seconds) |

### Command and Control (TA0011)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| Known C2 infrastructure | IOC feed matching (Feodo, C2 Tracker) | Block IP, terminate | Fast-path (< 1ms) |
| DGA domains | Entropy + consonant-vowel + bigram analysis | DNS sinkhole, alert | Real-time (ms) |
| Unusual outbound connections | Graph novelty detection (first-seen IP) | Alert, investigate | LLM (seconds) |
| Beaconing patterns | Temporal graph correlation | Alert, block connection | LLM (seconds) |

### Exfiltration (TA0010)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| Data staging + transfer | File access → network connection graph correlation | Alert, isolate network | LLM (seconds) |
| DNS tunneling | DGA detection + high-entropy subdomain analysis | DNS sinkhole | Real-time (ms) |
| Exfiltration to cloud storage | Domain reputation + graph chain context | Alert, block connection | LLM (seconds) |

### Lateral Movement (TA0008)

| Threat | Detection Method | Response Action | Speed |
|--------|-----------------|-----------------|-------|
| SSH lateral movement | Inbound auth → outbound connection graph correlation | Alert, block | LLM (seconds) |
| Remote tool execution | Process ancestry anomaly (sshd → unexpected child) | Alert, suspend | LLM (seconds) |
| Credential dumping | Chain-aware blocklist (`** > apache2 > cat /etc/shadow`) | SIGKILL | Fast-path (< 1ms) |

---

## Tactical Shell Matrix

Understanding which shells exist on which platforms is critical for threat modeling. Attackers choose shells based on target environment, and defenders must monitor all of them.

| Shell | Primary OS Environment | Tactical Target Vector |
|-------|----------------------|----------------------|
| `ash` | Alpine Linux, BusyBox, containers | Container breakouts, minimal environments — default shell in Docker Alpine images, often the first shell an attacker gets in a compromised container |
| `bash` | RHEL, CentOS, Fedora, Ubuntu (legacy default) | Enterprise Linux infrastructure — the most common interactive shell on production servers, CI/CD runners, and jump boxes |
| `dash` | Ubuntu, Debian (default `/bin/sh`) | Cloud infrastructure — Ubuntu is the dominant cloud OS; `dash` handles all `#!/bin/sh` scripts, making it invisible to bash-only monitoring |
| `sh` | Universal POSIX | Cross-platform pivoting — guaranteed to exist on every Unix system; attackers use it for maximum portability across unknown environments |
| `zsh` | macOS (default since Catalina) | Developer endpoints — macOS developer machines are high-value targets for supply chain attacks; `zsh` is the default interactive shell |
| `ksh` / `csh` / `tcsh` | AIX, Solaris, FreeBSD, legacy Unix | Legacy infrastructure — mainframes, financial systems, telecom equipment running decades-old Unix variants |

All shell binaries are monitored by eDR-Graph's process activity collection. Chain-aware rules can target specific shell invocations in context (e.g., `** > apache2 > bash` triggers differently than `sshd > bash`).

![IOC/IOA — DNS queries with DGA scoring, external IPs with geolocation, finding correlation](../screenshots/ioc-ioa.png)

---

## Detection Layer Mapping

| Layer | What It Catches | Latency | Requires LLM |
|-------|----------------|---------|--------------|
| **Fast-path blocklist** | Known-bad IPs, domains, CIDRs, process names, file paths, chain patterns | < 1 ms | No |
| **IOC feed matching** | Botnet C2, malware domains, malicious hashes (~50K indicators) | < 1 ms | No |
| **DGA detector** | Algorithmically generated domain names | < 1 ms | No |
| **Persistence detector** | LaunchAgent/Daemon, Registry Run keys, cron/systemd modifications | < 1 ms | No |
| **Code signing verification** | Unsigned or tampered binaries (macOS) | < 10 ms | No |
| **Graph novelty filter** | First-seen processes, IPs, domains, user-process relationships | ~1 ms | No (preflight) |
| **LLM threat analyzer** | Novel tradecraft, LOLBin abuse, multi-step attack patterns | 2-30s | Yes |
| **Process hierarchy intelligence** | Anomalous parent-child relationships | < 1 ms | No (pre-enrichment) |

---

## Response Mode Behavior per Detection Type

| Detection Source | Learning | Passive | Active |
|-----------------|----------|---------|--------|
| Fast-path blocklist match | Skipped | Alert only | **Block immediately** — SIGKILL + CRITICAL finding |
| IOC feed match | Record to baseline | Alert (CRITICAL finding) | Alert + response action |
| DGA detection | Record to baseline | Alert (finding) | Alert + DNS sinkhole |
| Persistence detection | Record to baseline | Alert (finding) | Alert + quarantine |
| LLM severity verdict | Record to baseline | Finding + alert | Finding → blocklist → allowlist → baseline → policy → approval → action |
| Tamper detection | Alert (always) | Alert (always) | Alert (always) |
