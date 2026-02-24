# Industry Comparisons

Where eDR-Graph fits in the endpoint security landscape, and where it doesn't.

---

## Tier 1: Legacy Antivirus

**Examples:** ClamAV, Malwarebytes, Windows Defender (signature mode)

Legacy AV relies on signature databases and point-in-time file hash matching. It scans files on disk and compares hashes against known malware signatures.

| Capability | Legacy AV | eDR-Graph |
|-----------|----------|-----------|
| **Detection model** | Signature matching (hashes, byte patterns) | Graph correlation + behavioral analysis + IOC feeds |
| **Behavioral analysis** | None or basic heuristics | LLM-driven reasoning with full attack chain context |
| **Response actions** | Quarantine file, delete file | 8 actions: suspend, terminate, isolate network, block IP, quarantine, DNS sinkhole, panic isolate |
| **Attack chain visibility** | None — point-in-time file scan | Full temporal graph: process → network → file → registry → DNS |
| **Zero-day detection** | None (requires signature update) | LLM analyzes novel behaviors, DGA detection, process ancestry anomalies |
| **Cost** | Free or low-cost | Free (open-source) + API costs for LLM/threat intel |

**Where Legacy AV wins:** Zero configuration, zero overhead, decades of signature coverage for known malware families.

**Where eDR-Graph wins:** Everything else — behavioral detection, attack chain correlation, real-time enforcement, LOLBin detection, and zero-day investigation. Legacy AV is completely blind to fileless attacks, living-off-the-land techniques, and multi-step attack chains.

---

## Tier 2: Enterprise XDR

**Examples:** CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint, Palo Alto Cortex XDR

Enterprise XDR platforms combine kernel-level sensors, cloud-scale data lakes, and proprietary AI models into fully managed security platforms.

| Capability | Enterprise XDR | eDR-Graph |
|-----------|---------------|-----------|
| **Kernel integration** | Ring-0 drivers (kernel modules, ELAM) | User-space (eBPF on Linux, no ESF on macOS) |
| **Cloud dependency** | Mandatory — all analysis in vendor cloud | Optional — LLM API for novel threats, local for everything else |
| **AI model transparency** | Black box (proprietary models) | Glass box — Gemma3-27B with visible prompts, tool calls, and reasoning |
| **Data sovereignty** | Telemetry sent to vendor cloud | All data stays on-endpoint (fleet mode sends only findings, not raw telemetry) |
| **Tamper protection** | Kernel-level (survives root compromise) | User-space only (root attacker can kill agent) |
| **Scale** | 100K+ endpoints with central management | Single endpoint (fleet mode for finding aggregation) |
| **Compliance certifications** | SOC 2, FedRAMP, HIPAA, PCI-DSS | None |
| **Cost** | $15-50+/endpoint/month | Free (open-source) + ~$5-20/month LLM API |

**Where Enterprise XDR wins:**

- **Kernel-level tamper protection** — Ring-0 drivers that survive root compromise
- **Certified compliance** — SOC 2, FedRAMP, HIPAA certifications for regulated industries
- **Fleet management** — Central console managing 100K+ endpoints with orchestrated response
- **Threat intelligence** — Massive proprietary datasets from millions of endpoints
- **SLA-backed support** — 24/7 managed detection and response (MDR)

**Where eDR-Graph offers advantages:**

- **Data sovereignty** — All telemetry stays on the endpoint. No data leaves your control unless you opt into fleet forwarding (and even then, only findings, not raw events).
- **AI transparency** — Every LLM analysis is visible: the prompt, the tool calls, the reasoning chain, and the final verdict. No black-box AI making opaque decisions.
- **Graph-first architecture** — Temporal property graph enables attack chain queries that flat-log XDR platforms cannot express natively.
- **Cost** — Open-source agent with minimal API costs vs. $15-50+/endpoint/month.
- **Customizable AI** — Swap LLM models, add tools, modify prompts, tune thresholds. Enterprise XDR AI is locked down.
- **No vendor lock-in** — Your data is in SQLite and Kuzu, exportable at any time.

---

## Tier 3: Open-Source EDR

**Examples:** Wazuh, OSSEC, Velociraptor, osquery

Open-source EDR tools provide log collection, rule-based detection, and incident response capabilities without vendor lock-in.

| Capability | Open-Source EDR | eDR-Graph |
|-----------|----------------|-----------|
| **Detection model** | Rule-based (YARA, Sigma, custom rules) | Graph correlation + LLM behavioral analysis + rules |
| **Graph database** | None (flat logs, SQL/Elasticsearch) | Embedded Kuzu property graph |
| **AI/ML analysis** | None or basic anomaly detection | LLM agentic tool-use with graph context |
| **Real-time enforcement** | Alert only (Wazuh active response is basic) | Fast-path blocklist (< 1ms) + LLM-driven response (8 actions) |
| **Process ancestry tracking** | Limited (parent PID only) | Full temporal chain with user identity and chain-aware rules |
| **Chain-aware rules** | Not supported | `>` separated patterns with `*`/`**` wildcards and `USER:` scoping |

**Where Open-Source EDR wins:**

- **Maturity** — Wazuh and OSSEC have decades of production deployment experience
- **Community rules** — Thousands of pre-written Sigma/YARA rules
- **SIEM integration** — Native integration with Elasticsearch, Splunk, and other SIEMs
- **Scale** — Wazuh manages thousands of agents with central management
- **Compliance** — Better documentation and community experience with compliance frameworks

**Where eDR-Graph offers advantages:**

- **Graph correlation** — Attack chains are first-class objects, not post-hoc log queries
- **LLM investigation** — Novel threats are investigated by an AI with tool-use, not just matched against rules
- **Sub-millisecond enforcement** — Fast-path blocklist provides EPP-grade blocking, not just alerting
- **Chain-aware rules** — Rules scoped to process ancestry and user identity, not just flat attributes
- **Identity-aware enforcement** — `USER:intern > ** > bash` is blocked while `USER:sysadmin > ** > bash` is allowed

---

## When to Use eDR-Graph

### Good Fit

- **Security research and education** — Transparent architecture for learning how EDR systems work
- **Small deployments** (1-50 endpoints) — Research labs, home networks, small dev teams
- **Data sovereignty requirements** — All telemetry stays on-endpoint, no cloud dependency
- **Transparent AI requirements** — Need to audit every AI decision (prompt, tools, reasoning)
- **Learning and experimentation** — Understanding endpoint detection, attack chain correlation, and LLM security applications
- **Budget-constrained environments** — Open-source with minimal API costs

### Not a Good Fit

- **Certified compliance** (SOC 2, FedRAMP, HIPAA) — No compliance certifications
- **Kernel-level tamper protection** — User-space agent, root attacker can disable it
- **Large fleet management** (1000+ endpoints) — No central orchestration console
- **Managed detection and response (MDR)** — No 24/7 SOC team or SLA-backed response
- **Environments requiring Apple ESF** — macOS detection is post-execution only

---

## eDR-Graph Differentiators

Four architectural properties that distinguish eDR-Graph from existing solutions:

1. **Glass-Box AI** — Every LLM analysis is fully auditable. The prompt, tool calls, reasoning chain, and final verdict are all visible in the finding detail. No opaque "AI detected a threat" — you can see exactly why.

2. **Temporal Graph Correlation** — Entities and relationships are stored in a property graph with timestamps. Attack chains are reconstructed by walking edges, not searching flat logs. Chain-aware rules can express patterns like "any process spawned by Apache that connects to an external IP" — impossible in flat-log systems.

3. **Memory-Safe eBPF Enforcement** — On Linux, eBPF tracepoints provide kernel-level telemetry without kernel module risks. Combined with the fast-path blocklist, this enables enforcement at the syscall level.

4. **Cost-Governed API Intelligence** — The graph novelty filter reduces LLM API calls by 95-99%, sending only genuinely novel behaviors for investigation. This makes LLM-powered threat analysis economically viable for continuous endpoint monitoring.
