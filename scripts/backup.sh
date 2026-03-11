#!/usr/bin/env bash
# AgentAuth — Database Backup Script
#
# Backs up PostgreSQL (pg_dump) and Redis (RDB snapshot) using GFS rotation:
#   - Daily:   keep 7 backups  (last 7 days)
#   - Weekly:  keep 4 backups  (every Sunday, last 4 weeks)
#   - Monthly: keep 3 backups  (1st of month, last 3 months)
#
# Usage:
#   ./scripts/backup.sh            # normal backup run
#   ./scripts/backup.sh --dry-run  # show what would happen, no changes
#
# Environment variables (override via .env or shell):
#   BACKUP_DIR      local directory to store backups (default: /opt/agentauth/backups)
#   BACKUP_REMOTE   rclone remote path for offsite copy (e.g. r2:agentauth-backups)
#                   leave empty to skip offsite sync
#   POSTGRES_CONTAINER  docker container name for postgres (default: auto-detect)
#   REDIS_CONTAINER     docker container name for redis   (default: auto-detect)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

BACKUP_DIR="${BACKUP_DIR:-/opt/agentauth/backups}"
BACKUP_REMOTE="${BACKUP_REMOTE:-}"

DAILY_KEEP=7
WEEKLY_KEEP=4    # in weeks (28 days)
MONTHLY_KEEP=3   # in months (90 days)

TIMESTAMP=$(date -u +"%Y-%m-%d")
DOW=$(date -u +"%u")    # 1=Monday … 7=Sunday
DOM=$(date -u +"%d")    # day of month

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

log() {
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [backup] $*"
}

die() {
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [backup] ERROR: $*" >&2
  exit 1
}

run() {
  if $DRY_RUN; then
    log "DRY-RUN: $*"
  else
    "$@"
  fi
}

# ── Detect containers ─────────────────────────────────────────────────────────

detect_container() {
  local pattern="$1"
  local override_var="$2"
  local override="${!override_var:-}"

  if [[ -n "$override" ]]; then
    echo "$override"
    return
  fi

  local name
  name=$(docker ps --format '{{.Names}}' | grep -E "$pattern" | head -1)
  if [[ -z "$name" ]]; then
    die "No running container matching '$pattern'. Set $override_var to override."
  fi
  echo "$name"
}

PG_CONTAINER=$(detect_container "postgres" "POSTGRES_CONTAINER")
REDIS_CONTAINER=$(detect_container "redis" "REDIS_CONTAINER")

log "Using PostgreSQL container: $PG_CONTAINER"
log "Using Redis container:      $REDIS_CONTAINER"

# ── Setup directories ─────────────────────────────────────────────────────────

PG_DAILY_DIR="$BACKUP_DIR/postgres/daily"
PG_WEEKLY_DIR="$BACKUP_DIR/postgres/weekly"
PG_MONTHLY_DIR="$BACKUP_DIR/postgres/monthly"
REDIS_DAILY_DIR="$BACKUP_DIR/redis/daily"

run mkdir -p "$PG_DAILY_DIR" "$PG_WEEKLY_DIR" "$PG_MONTHLY_DIR" "$REDIS_DAILY_DIR"

# ── PostgreSQL backup ─────────────────────────────────────────────────────────

pg_backup() {
  local dest_dir="$1"
  local label="$2"
  local dest_file="$dest_dir/agentauth_pg_${TIMESTAMP}_${label}.dump"

  log "Starting PostgreSQL $label backup → $dest_file"

  # pg_dump inside the container; --format=custom produces a compressed binary
  # that supports parallel restore and selective table restore
  run docker exec "$PG_CONTAINER" \
    pg_dump \
      --username="${POSTGRES_USER:-agentauth}" \
      --format=custom \
      --compress=9 \
      --no-password \
      "${POSTGRES_DB:-agentauth}" \
    > "$dest_file"

  local size
  size=$(du -sh "$dest_file" 2>/dev/null | cut -f1 || echo "unknown")
  log "PostgreSQL $label backup complete: $dest_file ($size)"
}

# ── Redis backup ──────────────────────────────────────────────────────────────

redis_backup() {
  local dest_dir="$1"
  local label="$2"
  local dest_file="$dest_dir/agentauth_redis_${TIMESTAMP}_${label}.rdb"

  log "Starting Redis $label backup → $dest_file"

  # Trigger a synchronous RDB save, then copy the file out of the container
  run docker exec "$REDIS_CONTAINER" redis-cli BGSAVE
  # Wait for the background save to complete (poll LASTSAVE)
  if ! $DRY_RUN; then
    local before
    before=$(docker exec "$REDIS_CONTAINER" redis-cli LASTSAVE)
    local attempts=0
    while true; do
      sleep 1
      local after
      after=$(docker exec "$REDIS_CONTAINER" redis-cli LASTSAVE)
      if [[ "$after" != "$before" ]]; then
        break
      fi
      (( attempts++ ))
      if (( attempts >= 30 )); then
        die "Redis BGSAVE did not complete within 30 seconds"
      fi
    done
  fi

  run docker cp "${REDIS_CONTAINER}:/data/dump.rdb" "$dest_file"

  local size
  size=$(du -sh "$dest_file" 2>/dev/null | cut -f1 || echo "unknown")
  log "Redis $label backup complete: $dest_file ($size)"
}

# ── Run backups ───────────────────────────────────────────────────────────────

# Daily backup — always
pg_backup "$PG_DAILY_DIR" "daily"
redis_backup "$REDIS_DAILY_DIR" "daily"

# Weekly backup — on Sundays (DOW=7)
if [[ "$DOW" == "7" ]]; then
  log "Sunday detected — creating weekly backup"
  pg_backup "$PG_WEEKLY_DIR" "weekly"
fi

# Monthly backup — on the 1st of the month
if [[ "$DOM" == "01" ]]; then
  log "First of month detected — creating monthly backup"
  pg_backup "$PG_MONTHLY_DIR" "monthly"
fi

# ── GFS Rotation ─────────────────────────────────────────────────────────────

rotate() {
  local dir="$1"
  local keep_days="$2"
  local label="$3"

  log "Rotating $label backups in $dir (keep: ${keep_days}d)"
  if ! $DRY_RUN; then
    find "$dir" -maxdepth 1 -type f -mtime "+${keep_days}" -print -delete
  else
    find "$dir" -maxdepth 1 -type f -mtime "+${keep_days}" -print | while read -r f; do
      log "DRY-RUN: would delete $f"
    done
  fi
}

rotate "$PG_DAILY_DIR"    "$DAILY_KEEP"           "PG daily"
rotate "$PG_WEEKLY_DIR"   $(( WEEKLY_KEEP * 7 ))  "PG weekly"
rotate "$PG_MONTHLY_DIR"  $(( MONTHLY_KEEP * 30 )) "PG monthly"
rotate "$REDIS_DAILY_DIR" "$DAILY_KEEP"            "Redis daily"

# ── Offsite sync (optional) ───────────────────────────────────────────────────

if [[ -n "$BACKUP_REMOTE" ]]; then
  if command -v rclone &>/dev/null; then
    log "Syncing backups to remote: $BACKUP_REMOTE"
    run rclone sync "$BACKUP_DIR" "$BACKUP_REMOTE" \
      --transfers=4 \
      --log-level=INFO
    log "Offsite sync complete"
  else
    log "WARNING: BACKUP_REMOTE is set but rclone is not installed — skipping offsite sync"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

log "Backup run complete."
if ! $DRY_RUN; then
  log "Disk usage: $(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)"
fi
