"""SQLite schema and pragmas for event queue and findings tables."""

import contextlib

PRAGMAS = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
]

EVENT_QUEUE_DDL = """
CREATE TABLE IF NOT EXISTS event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    processed INTEGER NOT NULL DEFAULT 0
)
"""

EVENT_QUEUE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_unprocessed
ON event_queue (processed, id) WHERE processed = 0
"""

FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_entities TEXT NOT NULL,
    evidence_event_ids TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    chain TEXT NOT NULL,
    affected_pids TEXT NOT NULL DEFAULT '[]',
    iocs TEXT NOT NULL DEFAULT '{}'
)
"""

FINDINGS_TIME_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_time ON findings (timestamp DESC)
"""

FINDINGS_SEVERITY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)
"""

RESPONSE_AUDIT_DDL = """
CREATE TABLE IF NOT EXISTS response_audit (
    response_id TEXT PRIMARY KEY,
    event_id INTEGER,
    timestamp TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    target_pid INTEGER,
    target_path TEXT,
    llm_severity TEXT,
    llm_confidence REAL,
    approved_by TEXT,
    approval_status TEXT NOT NULL DEFAULT 'auto',
    result TEXT NOT NULL DEFAULT 'pending',
    result_detail TEXT,
    reverted INTEGER NOT NULL DEFAULT 0,
    revert_timestamp TEXT
)
"""

RESPONSE_AUDIT_TIME_INDEX = """
CREATE INDEX IF NOT EXISTS idx_response_audit_time ON response_audit (timestamp DESC)
"""

RESPONSE_AUDIT_EVENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_response_audit_event ON response_audit (event_id)
"""

BEHAVIOR_BASELINE_DDL = """
CREATE TABLE IF NOT EXISTS behavior_baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name TEXT NOT NULL,
    behavior_type TEXT NOT NULL,
    target TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL DEFAULT 'learning',
    UNIQUE(process_name, behavior_type, target)
)
"""

RESPONSE_ALLOWLIST_DDL = """
CREATE TABLE IF NOT EXISTS response_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    chain_filter TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    created_by TEXT NOT NULL DEFAULT 'user'
)
"""

RESPONSE_BLOCKLIST_DDL = """
CREATE TABLE IF NOT EXISTS response_blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    chain_filter TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    created_by TEXT NOT NULL DEFAULT 'user'
)
"""

FORWARDING_QUEUE_DDL = """
CREATE TABLE IF NOT EXISTS forwarding_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_retry_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
)
"""

FORWARDING_QUEUE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_forwarding_pending
ON forwarding_queue (status, id) WHERE status = 'pending'
"""

ALL_DDL = [
    EVENT_QUEUE_DDL,
    EVENT_QUEUE_INDEX,
    FINDINGS_DDL,
    FINDINGS_TIME_INDEX,
    FINDINGS_SEVERITY_INDEX,
    RESPONSE_AUDIT_DDL,
    RESPONSE_AUDIT_TIME_INDEX,
    RESPONSE_AUDIT_EVENT_INDEX,
    BEHAVIOR_BASELINE_DDL,
    RESPONSE_ALLOWLIST_DDL,
    RESPONSE_BLOCKLIST_DDL,
    FORWARDING_QUEUE_DDL,
    FORWARDING_QUEUE_INDEX,
]

# Migrations for existing databases (errors silently ignored if column exists)
SQLITE_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN affected_pids TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE findings ADD COLUMN iocs TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE response_allowlist ADD COLUMN chain_filter TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE response_blocklist ADD COLUMN chain_filter TEXT NOT NULL DEFAULT ''",
]


def init_queue_db(conn) -> None:
    """Initialize SQLite database with pragmas and schema."""
    for pragma in PRAGMAS:
        conn.execute(pragma)
    for ddl in ALL_DDL:
        conn.execute(ddl)
    for migration in SQLITE_MIGRATIONS:
        with contextlib.suppress(Exception):
            conn.execute(migration)
    conn.commit()
