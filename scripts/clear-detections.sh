#!/usr/bin/env bash
# clear-detections.sh — Purge all finding, incident, and chain data across
# the entire EDR fleet while preserving host registrations, agent config,
# user accounts, threat intel feeds, and the forensic ledger.
#
# Usage:
#   ./scripts/clear-detections.sh              # default: mp1001 fleet server
#   FLEET_HOST=10.0.0.1 ./scripts/clear-detections.sh
#
# What is cleared:
#   Fleet server (Neo4j):  Finding, ChainNode, Incident, IP, Domain nodes + all rels
#   Fleet server (SQLite): xdr_queries, incident_surveillance_logs,
#                          surveillance_pull_state, incident_ocsf_evidence,
#                          incident_diamond_assessments
#   Agent (queue.db):      findings, forwarding_queue, response_audit, event_queue
#
# What is preserved:
#   Neo4j Host nodes, user accounts, registration keys, threat intel,
#   forensic ledger, behavior baselines, response allow/blocklists
set -euo pipefail

FLEET_HOST="${FLEET_HOST:-10.199.0.5}"
SSH_KEY="${SSH_KEY:-/Users/thomas/.ssh/mp1001}"
SSH="ssh -i $SSH_KEY root@$FLEET_HOST"
NEO4J_CONTAINER="edr-graph-neo4j-1"
FLEET_CONTAINER="edr-graph-fleet-server-1"
LOCAL_QUEUE_DB="/var/lib/edr-graph/queue.db"

cyan()  { printf '\033[36m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

neo4j_cmd() {
    local query="$1"
    $SSH "docker exec $NEO4J_CONTAINER cypher-shell \
        -u neo4j \
        -p \"\$(grep NEO4J_PASSWORD /opt/edr-graph/.env | cut -d= -f2)\" \
        '$query'" 2>/dev/null
}

# ── Step 1: Stop agents to prevent new data while clearing ──────────────
cyan "1. Stopping agents..."
$SSH "systemctl stop edr-agent" 2>/dev/null && green "   mp1001 agent stopped" || red "   mp1001 agent not running"
launchctl kill SIGTERM system/com.edgeaspect.edr-graph 2>/dev/null && green "   Local macOS agent stopped" || true
sleep 2  # Let the process exit

# ── Step 2: Clear Neo4j detection data ──────────────────────────────────
cyan "2. Clearing Neo4j detection data..."
for node_type in ChainNode Finding Incident IP Domain; do
    neo4j_cmd "MATCH (n:${node_type}) DETACH DELETE n RETURN count(n) AS deleted" \
        | grep -v '^deleted$' | while read -r cnt; do
            green "   Deleted $cnt $node_type nodes"
        done
done

# ── Step 3: Clear fleet server SQLite tables ────────────────────────────
cyan "3. Clearing fleet server SQLite tables..."
$SSH "docker exec $FLEET_CONTAINER python3 -c \"
import sqlite3, os
db = sqlite3.connect(os.environ.get('SETTINGS_DB_PATH', '/app/data/settings.db'))
tables = ['xdr_queries', 'incident_surveillance_logs', 'surveillance_pull_state',
          'incident_ocsf_evidence', 'incident_diamond_assessments']
for t in tables:
    try:
        cur = db.execute(f'DELETE FROM {t}')
        print(f'   {t}: {cur.rowcount} rows')
    except Exception as e:
        print(f'   {t}: skipped ({e})')
db.commit()
db.close()
\"" && green "   Fleet SQLite cleared"

# ── Step 4: Clear remote agent (mp1001) queue.db ───────────────────────
cyan "4. Clearing mp1001 agent queue.db..."
$SSH "python3 -c \"
import sqlite3
db = sqlite3.connect('/var/lib/edr-graph/queue.db')
tables = ['findings', 'forwarding_queue', 'response_audit', 'event_queue']
for t in tables:
    try:
        cur = db.execute(f'DELETE FROM {t}')
        print(f'   {t}: {cur.rowcount} rows')
    except Exception as e:
        print(f'   {t}: skipped ({e})')
db.commit()
db.close()
\"" && green "   mp1001 queue.db cleared"

# ── Step 5: Clear local macOS agent queue.db ────────────────────────────
cyan "5. Clearing local macOS agent queue.db..."
if [ -f "$LOCAL_QUEUE_DB" ]; then
    python3 -c "
import sqlite3
db = sqlite3.connect('$LOCAL_QUEUE_DB')
tables = ['findings', 'forwarding_queue', 'response_audit', 'event_queue']
for t in tables:
    try:
        cur = db.execute(f'DELETE FROM {t}')
        print(f'   {t}: {cur.rowcount} rows')
    except Exception as e:
        print(f'   {t}: skipped ({e})')
db.commit()
db.close()
" && green "   Local queue.db cleared"
else
    red "   $LOCAL_QUEUE_DB not found — skipping"
fi

# ── Step 6: Restart fleet server (clears orchestrator in-memory state) ──
cyan "6. Restarting fleet server..."
$SSH "cd /opt/edr-graph && docker compose restart fleet-server" 2>&1 | grep -v '^$'
sleep 3
green "   Fleet server restarted"

# ── Step 7: Restart agents ──────────────────────────────────────────────
cyan "7. Restarting agents..."
$SSH "systemctl start edr-agent" 2>/dev/null && green "   mp1001 agent started" || red "   mp1001 agent start failed"
launchctl kickstart -k system/com.edgeaspect.edr-graph 2>/dev/null \
    && green "   Local macOS agent restarted" \
    || red "   Local macOS agent not loaded"

# ── Step 8: Verify clean state ─────────────────────────────────────────
cyan "8. Verifying clean state..."
neo4j_cmd "MATCH (n) RETURN labels(n)[0] AS type, count(n) AS cnt ORDER BY cnt DESC" \
    | grep -v '^type, cnt$'
green "Done — all detection data cleared."
