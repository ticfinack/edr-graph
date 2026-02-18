# Phase 8: System Tray Icon + Local Web Dashboard

## Context

The agent is functionally complete on macOS with 359 tests passing. There is currently no user interface beyond terminal logs, `check_metrics.py`, and the Prometheus endpoint. This phase adds:

1. A native macOS menu bar (tray) icon for status, controls, and notifications
2. A local web dashboard for investigation, alert review, and graph visualization

The tray icon is the agent's face — it shows status at a glance and pushes macOS notifications for high-severity alerts. The web dashboard is where investigation happens — alert tables, process trees, graph views, and the response audit trail.

**Both run inside the agent process** to avoid the Kuzu concurrent reader problem. The web server is a thread inside the agent, not a separate process.

---

## Commit 1: Web Dashboard Backend (FastAPI)

### Create `agent/dashboard/server.py`

A FastAPI application that serves the dashboard UI and exposes REST API endpoints for the frontend.

#### Dependencies

```
fastapi>=0.110.0
uvicorn>=0.29.0
```

Run uvicorn in a thread inside the agent's main process. Bind to `127.0.0.1:9200` (configurable). This is separate from the Prometheus metrics port (9100).

#### API Endpoints

```
GET  /api/status
  Returns: {
    "agent_status": "running",
    "uptime_seconds": 1234,
    "collector_sources": ["unified_log", "tcpdump_dns", "psutil_network", "fsevents", "persistence_poller"],
    "events_processed": 12345,
    "events_dropped": 0,
    "events_per_second": 3.6,
    "queue_depth": 12,
    "buffer_size": 10000,
    "last_event_timestamp": "2025-02-17T10:30:00Z"
  }

GET  /api/findings?severity=HIGH&limit=50&offset=0&sort=timestamp_desc
  Returns: {
    "findings": [
      {
        "id": "...",
        "timestamp": "...",
        "severity": "HIGH",
        "title": "Persistence mechanism detected",
        "description": "Process python3 created LaunchAgent com.edr.test...",
        "mitre_technique": "T1543.001",
        "mitre_name": "Launch Agent",
        "source_pid": 1234,
        "source_process": "python3",
        "risk_indicators": [...],
        "llm_analysis": "...",
        "response_actions": [...]
      }
    ],
    "total": 42,
    "limit": 50,
    "offset": 0
  }

GET  /api/findings/:id
  Returns: Full finding detail with complete LLM analysis text and response audit trail.

GET  /api/graph/process-tree/:pid
  Returns: {
    "root": {
      "pid": 1,
      "name": "launchd",
      "children": [
        {
          "pid": 500,
          "name": "bash",
          "command_line": "/bin/bash",
          "children": [
            {
              "pid": 1234,
              "name": "python3",
              "command_line": "python3 malware.py",
              "children": []
            }
          ]
        }
      ]
    }
  }

GET  /api/graph/network/:pid
  Returns: {
    "process": {"pid": 1234, "name": "python3"},
    "domains": [
      {"name": "evil.com", "is_dga": true, "score": 0.82, "resolved_to": ["1.2.3.4"]}
    ],
    "connections": [
      {"ip": "1.2.3.4", "port": 443, "protocol": "tcp", "timestamp": "..."}
    ]
  }

GET  /api/graph/attack-chain/:pid
  Returns: The full output of build_attack_chain() for this PID.

GET  /api/graph/stats
  Returns: {
    "nodes": {"Process": 245, "IP": 41, "Domain": 28, "File": 99, "RegistryKey": 0, "User": 3},
    "edges": {"SPAWNED": 41, "CONNECTED_TO": 112, "RESOLVED": 54, "CREATED_FILE": 90, ...},
    "total_nodes": 416,
    "total_edges": 450
  }

GET  /api/metrics
  Returns: Parsed Prometheus metrics as JSON (reads from the in-process metrics, not HTTP scrape).

GET  /api/audit-trail?limit=50&offset=0
  Returns: Response action audit trail from SQLite. Each entry includes:
    action_taken, target_pid, target_path, severity, approved_by, timestamp, reverted.

GET  /api/events/recent?limit=100&source=all
  Returns: Most recent raw events from the processing pipeline (keep a circular buffer of last 1000 events in memory for this endpoint).

POST /api/response/approve/:response_id
  Body: {"action": "approve"} or {"action": "deny"}
  Approves or denies a pending response action. Only works if auto_respond is false.
```

#### Implementation Notes

- All graph queries go through `agent/graph/queries.py` functions. Do NOT write raw Kuzu queries in the dashboard server.
- SQLite queries for findings and audit trail use the existing DB connection from the agent process (same thread-safety approach as the rest of the agent).
- The recent events buffer is an in-memory `collections.deque(maxlen=1000)` that the graph processor appends to. The dashboard reads from it.
- All endpoints return JSON. No server-side HTML rendering.
- Add CORS headers for `127.0.0.1` only (the frontend is served from the same origin, but add it for development flexibility).

#### Tests

- Test each API endpoint returns correct JSON schema.
- Test findings filtering by severity.
- Test process tree endpoint builds correct hierarchy.
- Test that the server binds to localhost only (security).

---

## Commit 2: Dashboard Frontend

### Create `agent/dashboard/static/`

A single-page application served by FastAPI's static file handler. **Everything in one `index.html` file** — inline CSS, inline JS, no build step, no npm, no bundler. Use vanilla JS with `fetch()` for API calls.

#### Design Requirements

**Color scheme and aesthetic:**
- Dark theme. Background: `#0a0a0f`. Card backgrounds: `#12121a`. 
- Accent color for alerts and highlights: `#3b82f6` (blue). 
- Severity colors: CRITICAL `#ef4444` (red), HIGH `#f97316` (orange), MEDIUM `#eab308` (yellow), LOW `#22c55e` (green), INFO `#6b7280` (gray).
- Font: system font stack (`-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif`).
- Clean, minimal, information-dense. Think security operations center, not marketing page.
- Monospace font for PIDs, command lines, paths, IPs: `"SF Mono", "Menlo", monospace`.
- Subtle borders: `1px solid #1e1e2e`. No heavy shadows.

**Layout — single page with tab navigation:**

```
┌──────────────────────────────────────────────────────────┐
│  [icon] EDR Graph Agent    [●] Running   12.3 evt/s     │  ← Header bar
├────────┬────────┬────────┬────────┬────────┬─────────────┤
│Overview│Findings│ Graph  │ Events │ Audit  │  Settings   │  ← Tab bar
├────────┴────────┴────────┴────────┴────────┴─────────────┤
│                                                          │
│                    Tab Content                           │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### Tab 1: Overview

Status dashboard with key metrics in card layout:

```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Agent       │ │  Events     │ │  Findings   │ │  Graph      │
│  ● Running   │ │  12,345     │ │  42 total   │ │  416 nodes  │
│  Uptime: 2h  │ │  3.6/sec    │ │  5 HIGH     │ │  450 edges  │
│  0 dropped   │ │  Queue: 12  │ │  2 CRITICAL │ │  99 files   │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘

┌─ Active Collectors ──────────────────────────────────────┐
│  ✓ unified_log   ✓ tcpdump_dns   ✓ psutil_network      │
│  ✓ fsevents      ✓ persistence_poller                    │
└──────────────────────────────────────────────────────────┘

┌─ Recent Findings ───────────────────────────────────────┐
│  🔴 HIGH  T1543.001  LaunchAgent persistence   2m ago   │
│  🟡 MED   —          Encoded command exec      5m ago   │
│  🟢 LOW   —          Unusual DNS pattern       8m ago   │
└─────────────────────────────────────────────────────────┘
```

- Auto-refresh every 5 seconds via `setInterval` + `fetch("/api/status")`.
- Recent findings: show last 5, clickable to jump to Findings tab with that finding selected.

#### Tab 2: Findings

Sortable, filterable table of all findings:

```
┌─ Filters: [All Severities ▼] [All Techniques ▼] [Search...] ─┐
├────────┬──────────┬───────────────────────┬──────────┬────────┤
│Severity│ Time     │ Title                 │ ATT&CK   │ PID    │
├────────┼──────────┼───────────────────────┼──────────┼────────┤
│ 🔴 HIGH│ 10:30:15 │ Persistence detected  │ T1543.001│ 1234   │
│ 🟡 MED │ 10:28:02 │ Encoded command       │ —        │ 5678   │
│ 🟢 LOW │ 10:25:44 │ Unusual DNS           │ —        │ 9012   │
└────────┴──────────┴───────────────────────┴──────────┴────────┘
```

Clicking a row expands a detail panel below the table:

```
┌─ Finding Detail ─────────────────────────────────────────────┐
│                                                              │
│  Severity: HIGH        ATT&CK: T1543.001 (Launch Agent)     │
│  Process: python3 (PID 1234)                                 │
│  Command: python3 tests/live/attack_simulations.py           │
│  User: thomas                                                │
│  Time: 2025-02-17 10:30:15 UTC                               │
│                                                              │
│  ── LLM Analysis ──────────────────────────────────────────  │
│  The process created a LaunchAgent plist at                   │
│  ~/Library/LaunchAgents/com.edr.killchain.test.plist with    │
│  RunAtLoad=True. This is a persistence mechanism...          │
│                                                              │
│  ── Risk Indicators ───────────────────────────────────────  │
│  • Persistence: T1543.001 Launch Agent (HIGH)                │
│  • DGA candidate: xjk82mfq3p9a2z.xyz (score: 0.82)         │
│                                                              │
│  ── Response Actions ──────────────────────────────────────  │
│  [Alert sent] [Network isolation: awaiting_approval]         │
│                                                              │
│  [View Process Tree]  [View Network Graph]  [View Chain]     │
└──────────────────────────────────────────────────────────────┘
```

The "View Process Tree", "View Network Graph", and "View Chain" buttons switch to the Graph tab with the relevant PID loaded.

#### Tab 3: Graph

Interactive graph visualizations. Three sub-views selectable via toggle buttons:

**Process Tree View:**
- Render the process tree for a selected PID as an indented tree or a top-down hierarchy.
- Use SVG rendering (no external library — draw it with vanilla JS + SVG elements).
- Each node shows: process name, PID, and a severity badge if there are findings.
- Color-code nodes: red border if associated with HIGH/CRITICAL findings, default border otherwise.
- Clicking a node shows its details in a side panel.

**Network Graph View:**
- Show a selected process's network footprint: Process → Domain → IP.
- Layout: process node on the left, domain nodes in the middle, IP nodes on the right.
- DGA candidate domains highlighted in orange/red.
- Render with SVG. Edges as lines/arrows between nodes.

**Attack Chain View:**
- Full `build_attack_chain()` output rendered as a timeline or flow diagram.
- Stages: Process chain → Network activity → File activity → Persistence → Response actions.
- Each stage is a card in a horizontal or vertical flow.

**Implementation approach for all graph views:**
- Use inline SVG generated by JavaScript. No D3, no external graphing libraries.
- Keep it simple: rectangular nodes with text, lines for edges, color coding for severity.
- The graph doesn't need to be draggable or zoomable for v1. Just readable and clear.
- Add a PID search bar at the top of the Graph tab to look up any process.

#### Tab 4: Events

Live event stream showing the most recent events:

```
┌─ Event Stream (auto-refresh) ──── [Pause] [Filter: All ▼] ──┐
│                                                               │
│ 10:30:15.123  process_start   python3        PID:1234  ul    │
│ 10:30:15.456  dns_resolve     evil.com       PID:1234  dns   │
│ 10:30:15.789  file_create     /tmp/payload   —         fse   │
│ 10:30:16.012  network_connect 1.2.3.4:443    PID:1234  psu   │
│ 10:30:16.234  file_modify     backdoor.php   —         fse   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

- Auto-scrolling feed, newest at top.
- Color-coded by event type.
- Source abbreviation on the right (ul=unified_log, dns=tcpdump, fse=fsevents, psu=psutil, pp=persistence_poller).
- Filterable by event type and source.
- Pause button to freeze the stream for reading.
- Polls `/api/events/recent` every 2 seconds.

#### Tab 5: Audit Trail

Table of all response actions taken:

```
┌────────┬──────────┬─────────────────┬────────┬──────────┬─────────┐
│  Time  │  Action  │  Target         │Severity│ Approved │Reverted │
├────────┼──────────┼─────────────────┼────────┼──────────┼─────────┤
│10:30:15│ alert    │ PID 1234        │ HIGH   │ auto     │ —       │
│10:30:15│ isolate  │ PID 1234        │ HIGH   │ pending  │ —       │
│10:28:02│ log_only │ PID 5678        │ MEDIUM │ auto     │ —       │
└────────┴──────────┴─────────────────┴────────┴──────────┴─────────┘
```

- Pending approvals have an [Approve] [Deny] button that calls `POST /api/response/approve/:id`.
- Reverted actions are shown with strikethrough.

#### Tab 6: Settings

Read-only display of the current agent configuration. Shows:
- Collector configuration (which collectors are active, watched paths, etc.)
- Analysis settings (LLM model, DGA thresholds, persistence paths)
- Response policy (auto_respond, auto_terminate, protected processes)
- Dashboard port, metrics port

No editing — config changes require restarting the agent with a modified config.yaml. This tab is informational.

#### Frontend Technical Requirements

- **Single file: `index.html`** — all CSS in a `<style>` block, all JS in a `<script>` block. No external files except fonts (use system fonts, no CDN calls).
- **No frameworks.** Vanilla JS, `fetch()`, `document.createElement()` or template literals for DOM construction.
- **Responsive enough** to work at 1200px+ width. Not mobile-optimized (this is a desktop tool).
- **Auto-refresh** on Overview (5s), Events (2s), Findings (10s). Other tabs refresh on navigation.
- **URL hash routing** for tabs: `#overview`, `#findings`, `#graph`, `#events`, `#audit`, `#settings`. So you can link directly to a tab.
- **Keyboard shortcuts:** `1-6` to switch tabs, `r` to refresh current view, `p` to pause event stream.

### Tests

- Test that `GET /` serves the HTML page.
- Test that the HTML contains all 6 tab sections.
- Test that the page loads without any external network requests (no CDN dependencies).

---

## Commit 3: macOS Menu Bar Tray Icon

### Create `agent/tray/macos_tray.py`

Use the `rumps` library for a native macOS menu bar app.

#### Dependencies

```
rumps>=0.4.0; sys_platform == 'darwin'
```

#### Menu Bar Icon

- Use a simple circle indicator as the menu bar icon:
  - Green circle: agent running, no HIGH/CRITICAL findings in last hour
  - Orange circle: agent running, HIGH findings in last hour
  - Red circle: agent running, CRITICAL findings in last hour
  - Gray circle: agent stopped or unhealthy
- Generate these as small PNG icons programmatically at startup (use Pillow or embed base64 PNGs as constants — embedding is simpler and avoids the Pillow dependency).

#### Menu Structure

```
[●] EDR Graph Agent
├── Status: Running (2h 15m uptime)
├── Events: 12,345 processed (3.6/sec)
├── ──────────────
├── Findings: 42 total (5 HIGH, 2 CRITICAL)
├── Last Alert: Persistence detected (2m ago)
├── ──────────────
├── Open Dashboard        ⌘D
├── ──────────────
├── Collectors ▸
│   ├── ✓ Unified Log
│   ├── ✓ DNS (tcpdump)
│   ├── ✓ Network (psutil)
│   ├── ✓ FSEvents
│   └── ✓ Persistence Poller
├── ──────────────
├── Pause Agent
├── Resume Agent
├── ──────────────
└── Quit
```

#### macOS Notifications

Use `rumps.notification()` to send native macOS notifications for:

- **CRITICAL findings:** Immediate notification with sound. Title: "EDR CRITICAL Alert". Body: finding title + ATT&CK ID if available.
- **HIGH findings:** Notification without sound. Title: "EDR HIGH Alert". Body: finding title.
- **Agent health issues:** If events_dropped > 0 or queue_depth > 80% of buffer_size, notify once. Don't spam.
- **Rate limit:** Maximum 1 notification per severity per 60 seconds. Don't flood the notification center.

#### Implementation

- `rumps` requires running on the main thread (macOS AppKit constraint). Restructure agent startup:
  1. Main thread: `rumps` app event loop.
  2. Spawn agent pipeline (collectors, processor, analyzer, response engine, dashboard server) on background threads.
  3. The tray icon polls agent status via the same in-memory metrics used by the dashboard API.
- "Open Dashboard" menu item: calls `webbrowser.open("http://127.0.0.1:9200")`.
- "Pause Agent" / "Resume Agent": sets a flag that the processor thread checks. When paused, events are still collected but not processed (they buffer in the queue). This is useful for reducing LLM API usage when you're not actively monitoring.
- "Quit": calls agent shutdown (stop collectors, flush buffers, close DB connections, exit).

#### Notification Integration

Add a notification callback to the findings pipeline. When the LLM analyzer produces a finding:

```python
def on_finding(finding: Finding):
    if finding.severity in ("CRITICAL", "HIGH"):
        # Push to a thread-safe queue that the tray icon reads
        notification_queue.put(finding)
```

The tray icon's timer callback (runs every 2 seconds via `rumps.Timer`) checks this queue and dispatches macOS notifications.

#### Tests

- Test that the tray icon module imports correctly on macOS.
- Test notification rate limiting (2 CRITICAL findings within 60s should only produce 1 notification).
- Test menu item state reflects agent status (running/paused).
- Test that non-macOS platforms skip tray initialization gracefully.

---

## Commit 4: Integration and Startup Refactor

### Update `agent/main.py`

The agent startup needs restructuring to accommodate the tray icon's main-thread requirement.

#### New Startup Flow

```
main()
├── Load config
├── Initialize logging
├── Initialize metrics
├── Initialize database (SQLite + Kuzu)
├── Initialize collectors
├── Initialize graph processor
├── Initialize LLM analyzer
├── Initialize response engine
├── Start dashboard server thread (uvicorn on :9200)
├── Start collector threads
├── Start processor thread
├── Start analyzer thread
├── Start health server thread (:9100)
├── IF macOS AND tray_enabled:
│   ├── Start tray icon on main thread (rumps.App.run)
│   └── (rumps event loop takes over main thread)
├── ELSE:
│   └── Block on signal (SIGINT/SIGTERM) as before
└── Shutdown sequence (on quit or signal)
```

#### Config Additions

```yaml
dashboard:
  enabled: true
  port: 9200
  auto_open_browser: true  # Open dashboard in browser on startup

tray:
  enabled: true  # macOS only, ignored on other platforms
  notification_cooldown_seconds: 60
  notify_on_high: true
  notify_on_critical: true
```

#### CLI Additions

- `--no-dashboard` — disable the web dashboard
- `--no-tray` — disable the menu bar icon (run headless)
- `--dashboard-port PORT` — override dashboard port

#### Auto-Open Browser

If `dashboard.auto_open_browser` is true and the dashboard is enabled, open `http://127.0.0.1:9200` in the default browser 2 seconds after startup (delay to let uvicorn bind).

### Update Live Tests

Update `tests/live/run_live_tests.py`:
- Add a check that the dashboard is reachable at the configured port.
- Add a check that `GET /api/status` returns valid JSON.
- Add a check that `GET /` returns HTML.

### Update `tests/live/validate.py`:
- Switch from direct Kuzu access to using the dashboard API endpoints. This fixes the "can't query graph while agent is running" problem — the dashboard API runs inside the agent process and has access to Kuzu.
- Now validate.py can run WHILE the agent is running. All graph queries go through `GET /api/graph/*` endpoints.
- This should fix the Health endpoint FAIL and Attack chain FAIL from previous test runs.

---

## Cross-Cutting Requirements

### Security
- Dashboard server binds to `127.0.0.1` ONLY. Never `0.0.0.0`.
- No authentication for v1 (it's localhost-only). Add a `TODO` comment for future auth if the dashboard is exposed to a network.
- The approval endpoint (`POST /api/response/approve`) must validate the response_id exists and is in `pending` state before processing.

### Performance
- Dashboard API responses should be < 100ms. Graph queries that take longer should be cached with a short TTL (5 seconds).
- The recent events deque (1000 items) is shared between the processor thread and the API thread. Use a threading.Lock for access, but keep the critical section minimal.
- SVG graph rendering happens client-side in the browser. The API returns data, not rendered SVGs.

### Error Handling
- If the dashboard server fails to start (port in use), log a warning and continue running the agent headless. Dashboard failure should never prevent the agent from running.
- If `rumps` fails to initialize (not on macOS, or display server unavailable), fall back to headless mode with a warning.
- If a graph query fails in an API endpoint, return HTTP 500 with a JSON error body, don't crash the server.

### Dependencies

Add to requirements:
```
fastapi>=0.110.0
uvicorn>=0.29.0
rumps>=0.4.0; sys_platform == 'darwin'
```
