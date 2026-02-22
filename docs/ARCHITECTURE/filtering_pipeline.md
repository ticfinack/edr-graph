# eDR-Graph: Filtering Pipeline & Rules of Engagement (ROE)

## Architectural Philosophy

The eDR-Graph platform operates on a strict balance between **Microsecond Enforcement**, **Forensic Visibility**, and **Asynchronous Intelligence**.

When a process executes or a network connection is made, the telemetry travels through a deterministic pipeline. To write effective Allowlist and Blocklist rules without causing "Friendly Fire" or creating forensic blindspots, you must understand exactly when and how rules are evaluated.

---

## The 3 Operational Stages

### STAGE 1: Pre-Graph Allowlist (The "Radar" Filter)

**Goal:** Vaporize high-volume, 100% safe noise before it touches the database or the LLM.

**Action on Match:** The event is permanently dropped. No graph record is created, and the LLM never sees it.

**Supported Rule Types:** `process_name`, `dst_ip`, `dst_cidr`, `domain`, `file_path`.

**UNSUPPORTED Types:** `chain_pattern`, `finding_title`.

**The `chain_filter` Modifier:** IGNORED.

> **Architectural Warning:** Do not put dual-use binaries (like `perl`, `python`, `bash`) in the Pre-Graph Allowlist. Because this stage lacks chain context, allowing `python` here will blind the EDR to *all* python executions system-wide, destroying your forensic graph. Use this stage exclusively for deafening, harmless noise (e.g., macOS `mdworker`, trusted AV scanners).

---

### STAGE 2: Fast-Path Blocklist (The "Point Defense")

**Goal:** Instantly kill known malware signatures or hostile infrastructure before the LLM is even awake.

**Action on Match:** Instant SIGKILL to the process. Generates a Critical Alert. Bypasses the LLM entirely.

**Supported Rule Types:** `process_name`, `dst_ip`, `dst_cidr`, `domain`, `file_path`, `chain_pattern`.

**UNSUPPORTED Types:** `finding_title`.

**The `chain_filter` Modifier:** FULLY SUPPORTED. (Evaluates in O(1) time using the RAM-based PidIndex boot snapshot).

> **Tactical Example:** A rule for `file_path: "/etc/shadow"` WITH `chain_filter: "** > apache2 > **"` will ignore a root sysadmin reading the file, but will instantly snipe an Apache web worker attempting a credential dump.

---

### STAGE 3: Response Engine (The "Command Authority")

**Goal:** Act on the intelligence provided by the LLM, but verify it against Graph Database Ground Truth and ROE lists before acting.

**Action on Match (Allowlist):** Acts as a Safety Catch. Overrides the LLM and prevents the kill.

**Action on Match (Blocklist):** Executes the kinetic kill/quarantine action.

**Supported Rule Types:** ALL 7 TYPES.

**The `chain_filter` Modifier:** FULLY SUPPORTED. (Queries the Kuzu Graph database to get absolute deterministic proof of the process ancestry).

> **Tactical Example (The IFF Rule):** You have a Nextcloud container that legitimately runs `perl`. You create a Response Allowlist rule for `process_name: "perl"` WITH `chain_filter: "** > containerd-shim* > ** > perl"`.
>
> The event is recorded in the graph (preserving forensics). The LLM analyzes it. If the LLM hallucinates and flags the container, the Response Engine intercepts the order, checks the Ground Truth graph, matches your Allowlist rule, and vetoes the kill action.

---

## Rule Configuration Reference

Both allowlists and blocklists share the same 7 rule types. Each can optionally include a `chain_filter`.

| Rule Type | Pattern Format | Matches On |
|---|---|---|
| `process_name` | fnmatch glob | Process name (e.g., `perl`, `ncat*`) |
| `dst_ip` | exact IP | Destination IP address |
| `dst_cidr` | CIDR notation | Destination IP in range (e.g., `10.0.0.0/8`) |
| `domain` | exact domain | DNS domain (case-insensitive) |
| `file_path` | fnmatch glob | File path (e.g., `/tmp/evil*`) |
| `finding_title` | fnmatch glob | LLM finding title (Response Engine Stage Only) |
| `chain_pattern` | `>` separated names | Full process ancestry chain |

**The `chain_filter` Modifier:** An optional field on any rule representing a `>` separated chain pattern that must *also* match for the rule to apply. Wildcards: `*` matches exactly one step, `**` matches zero or more steps.

---

## The Decision Matrix

| If your objective is to... | Use this List | Can I use `chain_filter`? |
|---|---|---|
| Delete deafening noise so it doesn't fill up the hard drive or cost LLM tokens. | **Pre-Graph Allowlist** | **NO.** |
| Instantly snipe a known malicious IP, domain, or explicit attacker behavior. | **Fast-Path Blocklist** | **YES.** |
| Protect friendly automation (like Ansible or Docker) from being accidentally killed by the LLM. | **Response Engine Allowlist** | **YES.** |
