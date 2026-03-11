# AgentAuth Production Deployment Guide

## 1. Prerequisites

**VPS:** Hetzner CX21 or larger (2 vCPU, 4 GB RAM recommended)  
**OS:** Ubuntu 22.04 LTS  
**Domain:** Registered domain with Cloudflare DNS and Cloudflare Tunnel connector installed

Install required software:

```bash
# Docker + Docker Compose v2
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Nginx, Git, curl
sudo apt update && sudo apt install -y nginx git curl
```

Verify versions:

```bash
docker compose version   # must be v2
nginx -v
git --version
```

---

## 2. Initial Server Setup

**Create deploy user:**

```bash
sudo adduser admin
sudo usermod -aG sudo admin
sudo usermod -aG docker admin
```

**Configure SSH key-based auth:**

```bash
# On your local machine — copy your public key
ssh-copy-id admin@<your-server-ip>
```

**Disable password authentication** — edit `/etc/ssh/sshd_config`:

```
PasswordAuthentication no
PubkeyAuthentication yes
```

```bash
sudo systemctl reload sshd
```

**Configure UFW firewall:**

```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (Cloudflare Tunnel → Nginx)
sudo ufw enable
```

> Ports 8001 and 8002 (app slots) bind to `127.0.0.1` only and are never exposed publicly.

**Create project directory:**

```bash
sudo mkdir -p /home/admin/agentauth
sudo chown admin:admin /home/admin/agentauth
```

---

## 3. Cloudflare Tunnel Setup

**Install cloudflared:**

```bash
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install -y cloudflared
```

**Authenticate and create a tunnel:**

```bash
cloudflared tunnel login
cloudflared tunnel create agentauth
```

**Configure the tunnel** — create `~/.cloudflared/config.yml`:

```yaml
tunnel: agentauth
credentials-file: /home/admin/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: yourdomain.com
    service: http://localhost:80
  - service: http_status:404
```

**Run as a systemd service:**

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

---

## 4. Nginx Configuration

**Copy configuration files:**

```bash
sudo cp /home/admin/agentauth/nginx/agentauth.conf /etc/nginx/sites-available/agentauth
sudo cp /home/admin/agentauth/nginx/blue.conf /etc/nginx/conf.d/agentauth-blue.conf
sudo cp /home/admin/agentauth/nginx/green.conf /etc/nginx/conf.d/agentauth-green.conf
```

**Enable the site:**

```bash
sudo ln -s /etc/nginx/sites-available/agentauth /etc/nginx/sites-enabled/agentauth
sudo rm -f /etc/nginx/sites-enabled/default
```

**Set the initial active upstream to blue:**

```bash
sudo ln -sf /etc/nginx/conf.d/agentauth-blue.conf /etc/nginx/conf.d/agentauth-active.conf
```

**Test and reload Nginx:**

```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

## 5. Application Setup

**Clone the repository:**

```bash
git clone https://github.com/<your-org>/agent-auth.git /home/admin/agentauth
cd /home/admin/agentauth
```

**Create the `.env` file:**

```bash
cp .env.example .env
nano .env
```

Populate all required variables:

```dotenv
APP_NAME=AgentAuth
ENVIRONMENT=production
DEBUG=false

# DATABASE_URL and REDIS_URL are intentionally omitted here.
# docker-compose.prod.yml injects them with the correct Docker service hostnames
# (postgres:5432 and redis:6379). Setting them in .env would cause localhost
# to be used inside the container instead.

SECRET_KEY=your-secret-key-here          # generate: openssl rand -hex 32
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

API_V1_PREFIX=/api/v1
CORS_ORIGINS=["https://yourdomain.com"]

ADMIN_API_KEY=your-admin-api-key-here    # generate: openssl rand -hex 32

POSTGRES_DB=agentauth
POSTGRES_USER=agentauth
POSTGRES_PASSWORD=YOUR_DB_PASSWORD
```

**Create the initial slot state file:**

```bash
echo "blue" > /home/admin/agentauth/.active-slot
```

---

## 6. First Deployment Walkthrough

**Start infrastructure services only:**

```bash
cd /home/admin/agentauth
docker compose -f docker-compose.prod.yml up -d postgres redis
```

Wait until both containers are healthy:

```bash
docker compose -f docker-compose.prod.yml ps
```

**Run the initial database migrations:**

```bash
docker compose -f docker-compose.prod.yml run --rm app-blue uv run alembic upgrade head
```

**Run the full deployment script:**

```bash
bash scripts/deploy.sh
```

**Verify the application is running:**

```bash
# Check the blue slot directly
curl http://localhost:8001/health

# Check through Nginx
curl http://localhost/health
```

Both should return a `200 OK` response.

---

## 7. CI/CD Setup

The CI pipeline (`.github/workflows/ci.yml`) runs **lint-and-typecheck → test → deploy** on every push to `main`. The deploy step SSHes into the VPS and executes `bash scripts/deploy.sh`.

**Required GitHub Secrets** — add in _Settings > Secrets and variables > Actions_:

| Secret           | Description                       |
| ---------------- | --------------------------------- |
| `DEPLOY_HOST`    | IP address or hostname of the VPS |
| `DEPLOY_SSH_KEY` | Private SSH key (PEM format)      |

**Generate a dedicated SSH key pair for GitHub Actions:**

```bash
ssh-keygen -t ed25519 -C "github-actions-deploy" -f ~/.ssh/github_actions_deploy
```

**Add the public key to the VPS:**

```bash
cat ~/.ssh/github_actions_deploy.pub >> ~/.ssh/authorized_keys
```

**Add the private key to GitHub Secrets:**

Copy the contents of `~/.ssh/github_actions_deploy` (the private key) and paste it as the value of `DEPLOY_SSH_KEY` in GitHub.

---

## 8. Blue/Green Deployment

AgentAuth uses a zero-downtime blue/green strategy. Two application slots (`blue` on port 8001, `green` on port 8002) run independently. Nginx routes all traffic through a single symlink (`agentauth-active.conf`) that points to either `agentauth-blue.conf` or `agentauth-green.conf`. Swapping the symlink and reloading Nginx switches traffic instantly with no dropped connections.

**Normal deploy** (pulls latest code, rebuilds image, migrates, then cuts over):

```bash
bash scripts/deploy.sh
```

What happens step by step:

1. `git pull origin main`
2. `docker compose build` for the inactive slot
3. `uv run alembic upgrade head`
4. Start the inactive slot container
5. Health check with 30 s timeout (2 s interval) against `http://localhost:{port}/health`
6. Swap the Nginx symlink and reload Nginx
7. Stop the previously active slot
8. `docker image prune` to reclaim disk space

**Rollback** (reuses the existing image in the idle slot — no rebuild, no migration):

```bash
bash scripts/deploy.sh rollback
```

**Inspect current state:**

```bash
# Which slot is active?
cat /home/admin/agentauth/.active-slot

# Confirm the Nginx symlink target
ls -la /etc/nginx/conf.d/agentauth-active.conf
```

**Manual emergency slot switch** (if the deploy script is unavailable):

```bash
# Switch to green manually
sudo ln -sf /etc/nginx/conf.d/agentauth-green.conf /etc/nginx/conf.d/agentauth-active.conf
sudo systemctl reload nginx
echo "green" > /home/admin/agentauth/.active-slot
```

---

## 9. Monitoring and Maintenance

**Health checks by slot:**

```bash
curl http://localhost:8001/health   # blue slot
curl http://localhost:8002/health   # green slot
```

**View logs:**

```bash
# Stream all service logs
docker compose -f docker-compose.prod.yml logs -f
# Or via Makefile shorthand
make prod-logs
```

**Service status:**

```bash
make prod-ps
```

**Database backup:**

```bash
docker exec agentauth-postgres-1 pg_dump -U agentauth agentauth > backup-$(date +%Y%m%d).sql
```

**Docker image cleanup** (also runs automatically after each deploy):

```bash
docker image prune -f
```

**Log rotation:** Nginx log rotation is managed by `logrotate` automatically. Docker container logs are bounded via `--log-opt max-size` in the compose file.

---

## 10. Monitoring & Logging

AgentAuth ships with a full observability stack (Loki + Promtail + Grafana) that is started alongside the application in `docker-compose.prod.yml`.

### Services Overview

| Service      | Role                                                                           | Accessibility                                   |
| ------------ | ------------------------------------------------------------------------------ | ----------------------------------------------- |
| **Loki**     | Log storage and querying engine                                                | Internal only (port 3100, not exposed publicly) |
| **Promtail** | Log scraping agent — reads Docker container logs, parses JSON, extracts labels | Internal only                                   |
| **Grafana**  | Dashboard UI for log exploration and pre-built panels                          | `http://localhost:3000` (or via SSH tunnel)     |

### Starting the Monitoring Stack

The monitoring services start automatically with the production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Accessing Grafana

- **URL:** `http://localhost:3000` (access remotely via SSH tunnel: `ssh -L 3000:localhost:3000 admin@<your-server-ip>`)
- **Login:** `admin` / `$GRAFANA_PASSWORD` (defaults to `admin` if `GRAFANA_PASSWORD` is not set in `.env`)

Set a strong password in `.env`:

```dotenv
GRAFANA_PASSWORD=your-secure-grafana-password
```

After logging in, navigate to **Dashboards → AgentAuth Operations** to open the pre-built dashboard.

### Log Querying with LogQL

Grafana's Explore view accepts [LogQL](https://grafana.com/docs/loki/latest/query/) queries. Open **Explore**, select the **Loki** datasource, and try:

```logql
# All logs from the agentauth service in the last hour
{service="agentauth"}

# Only error-level logs
{service="agentauth"} | json | level="error"

# Requests to a specific API path
{service="agentauth"} | json | path="/api/v1/agents"

# Trace a single request end-to-end by request_id
{service="agentauth"} | json | request_id="<uuid>"

# Filter all activity for a specific agent
{service="agentauth"} | json | agent_id="<agent-id>"
```

### Log Retention

- **Default retention:** 30 days (720 h)
- **Configuration file:** `monitoring/loki-config.yml` — `limits_config.retention_period`
- **To change:** edit the value and restart Loki:

```bash
docker compose -f docker-compose.prod.yml restart loki
```

### Pre-built Dashboard Panels

The **AgentAuth Operations** dashboard is auto-provisioned on Grafana startup and contains:

| Panel                           | What it shows                                     |
| ------------------------------- | ------------------------------------------------- |
| **Request Rate**                | Request throughput grouped by HTTP status code    |
| **4xx Error Rate**              | Client error rate trend over time                 |
| **5xx Error Rate**              | Server error rate trend over time                 |
| **P50 / P95 / P99 Latency**     | Response time percentiles                         |
| **Authentication Failures**     | Failed auth attempts over time                    |
| **Rate Limit Hits**             | 429 responses over time (sliding-window breaches) |
| **Top Agents by Request Count** | Most active agents by request volume              |
| **Endpoint Breakdown**          | Traffic distribution per API path                 |

---

## 11. Backups

AgentAuth backs up **PostgreSQL** (full logical dump) and **Redis** (RDB snapshot) using a
**GFS (Grandfather-Father-Son) rotation** scheme.

### Retention policy

| Tier              | Frequency              | Retention | Files kept            |
| ----------------- | ---------------------- | --------- | --------------------- |
| Daily             | Every day at 02:00 UTC | 7 days    | 7                     |
| Weekly            | Every Sunday           | 4 weeks   | 4                     |
| Monthly           | 1st of month           | 3 months  | 3                     |
| **Total on disk** |                        |           | **≤ 14 PG + 7 Redis** |

Redis holds ephemeral data (rate-limit windows, token caches). AOF provides crash recovery;
the daily RDB snapshot is an additional safety net. Only daily rotation is applied to Redis.

### Scheduled backup (cron)

Add to the host's `/etc/cron.d/agentauth-backup`:

```cron
# Run backup daily at 02:00 UTC
0 2 * * *  root  /home/admin/agentauth/scripts/backup.sh >> /var/log/agentauth-backup.log 2>&1
```

### Environment variables

Set in `/home/admin/agentauth/.env` (or shell environment):

| Variable             | Default                         | Description                                                       |
| -------------------- | ------------------------------- | ----------------------------------------------------------------- |
| `BACKUP_DIR`         | `/home/admin/agentauth/backups` | Local directory for backup files                                  |
| `BACKUP_REMOTE`      | _(empty)_                       | rclone remote path for offsite sync (e.g. `r2:agentauth-backups`) |
| `POSTGRES_CONTAINER` | auto-detect                     | Docker container name for Postgres                                |
| `REDIS_CONTAINER`    | auto-detect                     | Docker container name for Redis                                   |

### Running a backup manually

```bash
# Via Makefile
make backup

# Directly
./scripts/backup.sh

# Dry run — see what would happen without making changes
./scripts/backup.sh --dry-run
```

### Listing available backups

```bash
make backup-list
```

Output example:

```
PostgreSQL backups:
  2026-03-11   1840 KB  /home/admin/agentauth/backups/postgres/daily/agentauth_pg_2026-03-11_daily.dump
  2026-03-10   1838 KB  /home/admin/agentauth/backups/postgres/daily/agentauth_pg_2026-03-10_daily.dump
  ...

Redis backups:
  2026-03-11     92 KB  /home/admin/agentauth/backups/redis/daily/agentauth_redis_2026-03-11_daily.rdb
  ...
```

### Verifying a backup

Before relying on a backup for restore, verify its contents:

```bash
# List tables and row counts in a pg_dump archive
docker exec agentauth-postgres-1 \
  pg_restore --list /tmp/agentauth_pg_2026-03-11_daily.dump 2>/dev/null | head -30
```

### Restoring from a backup

> ⚠ **Restore drops and recreates all database objects.** App slots are stopped automatically.

```bash
# Interactive (prompts for confirmation)
make backup-restore FILE=/home/admin/agentauth/backups/postgres/daily/agentauth_pg_2026-03-11_daily.dump

# Or call directly
./scripts/restore.sh /home/admin/agentauth/backups/postgres/daily/agentauth_pg_2026-03-11_daily.dump
```

After restore:

1. Verify the app is healthy: `make prod-ps`
2. Check for migration drift: `uv run alembic current`
3. Smoke-test the `/health` endpoint

### Offsite backup with rclone

Install [rclone](https://rclone.org) and configure a remote (e.g. Cloudflare R2, Backblaze B2, or S3):

```bash
rclone config   # follow prompts to add a remote named "r2"
```

Then set `BACKUP_REMOTE` in `.env`:

```env
BACKUP_REMOTE=r2:agentauth-backups
```

The backup script will call `rclone sync` after each run, mirroring the local `BACKUP_DIR`
to the remote. The same retention policy applies — old files are pruned locally before sync,
so the remote mirrors the local state.

---

## 12. Troubleshooting

**Deploy fails health check**

Check the logs for the slot that failed to start:

```bash
docker compose -f docker-compose.prod.yml logs app-blue
# or
docker compose -f docker-compose.prod.yml logs app-green
```

**Nginx 502 Bad Gateway**

Confirm which slot is supposed to be active and that its container is running:

```bash
cat /home/admin/agentauth/.active-slot
make prod-ps
```

**Database connection errors**

Verify the postgres container is healthy and that `DATABASE_URL` in `.env` matches `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB`:

```bash
docker compose -f docker-compose.prod.yml ps postgres
```

**Redis connection errors**

Verify the redis container is healthy and that `REDIS_URL` in `.env` is correct:

```bash
docker compose -f docker-compose.prod.yml ps redis
```

**CI deploy job fails**

Ensure both GitHub Secrets are configured in _Settings > Secrets and variables > Actions_: `DEPLOY_HOST`, `DEPLOY_SSH_KEY`.

**Migrations fail during deploy**

Run migrations manually against the target slot:

```bash
docker compose -f docker-compose.prod.yml run --rm app-blue uv run alembic upgrade head
```
