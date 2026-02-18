"""SQLite schema and pragmas for event queue and findings tables."""

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
    affected_pids TEXT NOT NULL DEFAULT '[]'
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

ALL_DDL = [
    EVENT_QUEUE_DDL,
    EVENT_QUEUE_INDEX,
    FINDINGS_DDL,
    FINDINGS_TIME_INDEX,
    FINDINGS_SEVERITY_INDEX,
    RESPONSE_AUDIT_DDL,
    RESPONSE_AUDIT_TIME_INDEX,
    RESPONSE_AUDIT_EVENT_INDEX,
]

# Migrations for existing databases (errors silently ignored if column exists)
SQLITE_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN affected_pids TEXT NOT NULL DEFAULT '[]'",
]


def init_queue_db(conn) -> None:
    """Initialize SQLite database with pragmas and schema."""
    for pragma in PRAGMAS:
        conn.execute(pragma)
    for ddl in ALL_DDL:
        conn.execute(ddl)
    for migration in SQLITE_MIGRATIONS:
        try:
            conn.execute(migration)
        except Exception:
            pass  # Column already exists
    conn.commit()
