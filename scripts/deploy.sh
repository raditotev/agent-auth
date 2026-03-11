#!/usr/bin/env bash
# =============================================================================
# AgentAuth Blue/Green Deploy Script
# =============================================================================
#
# USAGE:
#   ./scripts/deploy.sh            # Deploy latest to inactive slot and cut over
#   ./scripts/deploy.sh rollback   # Switch traffic back to the previously active slot
#
# HOW IT WORKS:
#   Two slots (blue/green) run on separate ports behind Nginx.
#   A symlink (/etc/nginx/conf.d/agentauth-active.conf) controls which slot
#   receives live traffic. A state file (/opt/agentauth/.active-slot) records
#   which slot is currently active so the script knows which to target next.
#
# REQUIREMENTS:
#   - Docker + Docker Compose v2 installed
#   - Nginx installed and managing /etc/nginx/conf.d/
#   - Run from the repo root on the VPS (default: /opt/agentauth)
#   - Nginx config files for each slot already present:
#       /etc/nginx/conf.d/agentauth-blue.conf   (upstream 127.0.0.1:8001)
#       /etc/nginx/conf.d/agentauth-green.conf  (upstream 127.0.0.1:8002)
#
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEPLOY_PATH="${DEPLOY_PATH:-/opt/agentauth}"
STATE_FILE="${DEPLOY_PATH}/.active-slot"
NGINX_CONF_DIR="/etc/nginx/conf.d"
ACTIVE_SYMLINK="${NGINX_CONF_DIR}/agentauth-active.conf"
COMPOSE_FILE="docker-compose.prod.yml"

BLUE_PORT=8001
GREEN_PORT=8002

HEALTH_INTERVAL=2   # seconds between health check polls
HEALTH_TIMEOUT=30   # total seconds to wait for healthy response

# -----------------------------------------------------------------------------
# ANSI color helpers
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log_info()    { echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${RESET}  $*"; }
log_success() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${RESET}  $*"; }
log_error()   { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${RESET} $*" >&2; }

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
opposite_slot() {
  [[ "$1" == "blue" ]] && echo "green" || echo "blue"
}

port_for_slot() {
  [[ "$1" == "blue" ]] && echo "${BLUE_PORT}" || echo "${GREEN_PORT}"
}

read_active_slot() {
  if [[ -f "${STATE_FILE}" ]]; then
    local slot
    slot="$(cat "${STATE_FILE}")"
    slot="${slot// /}"  # strip whitespace
    if [[ "${slot}" == "blue" || "${slot}" == "green" ]]; then
      echo "${slot}"
      return
    fi
  fi
  echo "none"
}

# Poll /health until HTTP 200 or timeout.
# Returns 0 on success, 1 on timeout.
wait_for_healthy() {
  local slot="$1"
  local port
  port="$(port_for_slot "${slot}")"
  local url="http://localhost:${port}/health"
  local elapsed=0

  log_info "Waiting for ${BOLD}${slot}${RESET} to become healthy at ${url} (timeout: ${HEALTH_TIMEOUT}s)"

  while (( elapsed < HEALTH_TIMEOUT )); do
    local http_code
    http_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 "${url}" 2>/dev/null || true)"
    if [[ "${http_code}" == "200" ]]; then
      log_success "${slot} is healthy (HTTP 200) after ${elapsed}s"
      return 0
    fi
    log_info "  attempt ${elapsed}s — got HTTP ${http_code:-???}, retrying in ${HEALTH_INTERVAL}s…"
    sleep "${HEALTH_INTERVAL}"
    (( elapsed += HEALTH_INTERVAL ))
  done

  log_error "${slot} did not become healthy within ${HEALTH_TIMEOUT}s"
  return 1
}

swap_nginx() {
  local target="$1"
  local target_conf="${NGINX_CONF_DIR}/agentauth-${target}.conf"

  if [[ ! -f "${target_conf}" ]]; then
    log_error "Nginx config not found: ${target_conf}"
    exit 1
  fi

  log_info "Swapping nginx symlink → ${target_conf}"
  ln -sf "${target_conf}" "${ACTIVE_SYMLINK}"
  nginx -s reload
  log_success "Nginx reloaded; traffic now routed to ${BOLD}${target}${RESET}"
}

update_state() {
  local slot="$1"
  echo "${slot}" > "${STATE_FILE}"
  log_success "State file updated: ${STATE_FILE} = ${slot}"
}

stop_slot() {
  local slot="$1"
  log_info "Stopping ${slot} slot…"
  docker compose -f "${COMPOSE_FILE}" stop "app-${slot}" || true
  log_success "${slot} stopped"
}

# -----------------------------------------------------------------------------
# Deploy
# -----------------------------------------------------------------------------
cmd_deploy() {
  echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  AgentAuth — Blue/Green Deploy${RESET}"
  echo -e "${BOLD}${CYAN}════════════════════════════════════════${RESET}\n"

  local current_slot
  current_slot="$(read_active_slot)"
  local target_slot

  if [[ "${current_slot}" == "none" ]]; then
    log_warn "No active slot found; defaulting target to ${BOLD}blue${RESET}"
    target_slot="blue"
  else
    target_slot="$(opposite_slot "${current_slot}")"
    log_info "Current active slot: ${BOLD}${current_slot}${RESET} → deploying to: ${BOLD}${target_slot}${RESET}"
  fi

  local target_port
  target_port="$(port_for_slot "${target_slot}")"

  # 1. Pull latest code
  log_info "Pulling latest code from origin/main…"
  git pull origin main
  log_success "git pull done"

  # 2. Build image
  log_info "Building Docker image…"
  docker compose -f "${COMPOSE_FILE}" build
  log_success "Image built"

  # 3. Run database migrations via the target slot service
  log_info "Running Alembic migrations via app-${target_slot}…"
  docker compose -f "${COMPOSE_FILE}" run --rm "app-${target_slot}" uv run alembic upgrade head
  log_success "Migrations applied"

  # 4. Start target slot
  log_info "Starting ${BOLD}${target_slot}${RESET} slot (port ${target_port})…"
  docker compose -f "${COMPOSE_FILE}" --profile "${target_slot}" up -d "app-${target_slot}"
  log_success "${target_slot} container started"

  # 5. Health check
  if wait_for_healthy "${target_slot}"; then
    # 6a. Healthy — cut over
    swap_nginx "${target_slot}"
    update_state "${target_slot}"

    if [[ "${current_slot}" != "none" ]]; then
      stop_slot "${current_slot}"
    fi

    log_info "Pruning old images…"
    docker image prune -f
    log_success "Image prune done"

    echo -e "\n${GREEN}${BOLD}✓ Deploy complete. Active slot: ${target_slot} (port ${target_port})${RESET}\n"
  else
    # 6b. Unhealthy — abort and stop target
    log_error "Deploy failed. Rolling back — stopping ${target_slot}…"
    stop_slot "${target_slot}"
    log_error "Check logs with: docker compose -f ${COMPOSE_FILE} logs app-${target_slot}"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Rollback
# -----------------------------------------------------------------------------
cmd_rollback() {
  echo -e "\n${BOLD}${YELLOW}════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${YELLOW}  AgentAuth — Rollback${RESET}"
  echo -e "${BOLD}${YELLOW}════════════════════════════════════════${RESET}\n"

  local current_slot
  current_slot="$(read_active_slot)"

  if [[ "${current_slot}" == "none" ]]; then
    log_error "No active slot recorded in ${STATE_FILE}. Cannot rollback."
    exit 1
  fi

  local target_slot
  target_slot="$(opposite_slot "${current_slot}")"
  local target_port
  target_port="$(port_for_slot "${target_slot}")"

  log_info "Rolling back: ${BOLD}${current_slot}${RESET} → ${BOLD}${target_slot}${RESET}"

  # Start previously stopped slot (no build, no migrations — reuses existing image)
  log_info "Starting ${BOLD}${target_slot}${RESET} slot (port ${target_port})…"
  docker compose -f "${COMPOSE_FILE}" --profile "${target_slot}" up -d "app-${target_slot}"
  log_success "${target_slot} container started"

  # Health check
  if wait_for_healthy "${target_slot}"; then
    swap_nginx "${target_slot}"
    update_state "${target_slot}"
    stop_slot "${current_slot}"

    echo -e "\n${GREEN}${BOLD}✓ Rollback complete. Active slot: ${target_slot} (port ${target_port})${RESET}\n"
  else
    log_error "Rollback failed — ${target_slot} did not become healthy."
    stop_slot "${target_slot}"
    log_error "Check logs with: docker compose -f ${COMPOSE_FILE} logs app-${target_slot}"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
main() {
  local command="${1:-deploy}"

  case "${command}" in
    deploy)   cmd_deploy ;;
    rollback) cmd_rollback ;;
    *)
      log_error "Unknown command: ${command}"
      echo "Usage: $0 [deploy|rollback]"
      exit 1
      ;;
  esac
}

main "$@"
