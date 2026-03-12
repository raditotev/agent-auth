#!/usr/bin/env bash
# AgentAuth — Database Restore Script
#
# Restores a PostgreSQL backup created by scripts/backup.sh.
# Stops app slots before restoring to avoid dirty writes, then restarts them.
#
# Usage:
#   ./scripts/restore.sh <path-to-backup.dump>
#
# Example:
#   ./scripts/restore.sh /home/admin/agentauth/backups/postgres/daily/agentauth_pg_2026-03-10_daily.dump
#
# The backup file must be a pg_dump --format=custom archive.

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────

log() {
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [restore] $*"
}

die() {
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [restore] ERROR: $*" >&2
  exit 1
}

confirm() {
  local prompt="$1"
  read -r -p "$prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ── Argument validation ───────────────────────────────────────────────────────

BACKUP_FILE="${1:-}"

if [[ -z "$BACKUP_FILE" ]]; then
  echo "Usage: $0 <path-to-backup.dump>"
  echo ""
  echo "Available backups:"
  BACKUP_DIR="${BACKUP_DIR:-/home/admin/agentauth/backups}"
  find "$BACKUP_DIR/postgres" -name "*.dump" -type f -printf "  %TY-%Tm-%Td %TH:%TM  %p\n" 2>/dev/null | sort || true
  exit 1
fi

[[ -f "$BACKUP_FILE" ]] || die "Backup file not found: $BACKUP_FILE"

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
  name=$(docker ps --format '{{.Names}}' | grep -E "$pattern" | head -1 || true)
  if [[ -z "$name" ]]; then
    # Also check stopped containers (postgres should be running for restore)
    name=$(docker ps -a --format '{{.Names}}' | grep -E "$pattern" | head -1 || true)
  fi
  if [[ -z "$name" ]]; then
    die "No container matching '$pattern'. Set $override_var to override."
  fi
  echo "$name"
}

PG_CONTAINER=$(detect_container "postgres" "POSTGRES_CONTAINER")

# ── Safety prompt ─────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AgentAuth — Database Restore"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Backup file : $BACKUP_FILE"
echo "  PG container: $PG_CONTAINER"
echo "  Database    : ${POSTGRES_DB:-agentauth}"
echo ""
echo "  ⚠  This will DROP and recreate all objects in the target database."
echo "     App slots will be stopped during the restore."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

confirm "Proceed with restore?" || { echo "Aborted."; exit 0; }

# ── Stop app slots ────────────────────────────────────────────────────────────

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"

if [[ -f "$COMPOSE_FILE" ]]; then
  log "Stopping app slots (blue + green) to prevent dirty writes..."
  docker compose -f "$COMPOSE_FILE" stop app-blue app-green 2>/dev/null || true
else
  log "WARNING: $COMPOSE_FILE not found — ensure app is not writing to the database"
fi

# ── Copy backup into container and restore ────────────────────────────────────

TEMP_CONTAINER_PATH="/tmp/agentauth_restore_$(date +%s).dump"

log "Copying backup file into container..."
docker cp "$BACKUP_FILE" "${PG_CONTAINER}:${TEMP_CONTAINER_PATH}"

log "Running pg_restore (--clean drops existing objects before recreating)..."
docker exec "$PG_CONTAINER" \
  pg_restore \
    --username="${POSTGRES_USER:-agentauth}" \
    --dbname="${POSTGRES_DB:-agentauth}" \
    --clean \
    --if-exists \
    --no-password \
    --verbose \
    "$TEMP_CONTAINER_PATH"

log "Cleaning up temp file in container..."
docker exec "$PG_CONTAINER" rm -f "$TEMP_CONTAINER_PATH"

# ── Restart app slots ─────────────────────────────────────────────────────────

if [[ -f "$COMPOSE_FILE" ]]; then
  ACTIVE_SLOT_FILE="${ACTIVE_SLOT_FILE:-/home/admin/agentauth/.active-slot}"
  ACTIVE_SLOT=""
  if [[ -f "$ACTIVE_SLOT_FILE" ]]; then
    ACTIVE_SLOT=$(cat "$ACTIVE_SLOT_FILE")
  fi

  if [[ -n "$ACTIVE_SLOT" ]]; then
    log "Restarting active slot: $ACTIVE_SLOT"
    docker compose -f "$COMPOSE_FILE" --profile "$ACTIVE_SLOT" start "app-${ACTIVE_SLOT}"
  else
    log "No active slot file found at $ACTIVE_SLOT_FILE"
    log "Start the desired slot manually: make prod-up-blue  OR  make prod-up-green"
  fi
fi

echo ""
log "Restore complete ✓"
echo ""
echo "Next steps:"
echo "  1. Verify the application is healthy: make prod-ps"
echo "  2. Run a smoke test against the /health endpoint"
echo "  3. Check for migration drift: uv run alembic current"
