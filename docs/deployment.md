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
sudo adduser deploy
sudo usermod -aG sudo deploy
sudo usermod -aG docker deploy
```

**Configure SSH key-based auth:**

```bash
# On your local machine — copy your public key
ssh-copy-id deploy@<your-server-ip>
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
sudo mkdir -p /opt/agentauth
sudo chown deploy:deploy /opt/agentauth
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
credentials-file: /home/deploy/.cloudflared/<tunnel-id>.json

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
sudo cp /opt/agentauth/nginx/agentauth.conf /etc/nginx/sites-available/agentauth
sudo cp /opt/agentauth/nginx/blue.conf /etc/nginx/conf.d/agentauth-blue.conf
sudo cp /opt/agentauth/nginx/green.conf /etc/nginx/conf.d/agentauth-green.conf
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
git clone https://github.com/<your-org>/agent-auth.git /opt/agentauth
cd /opt/agentauth
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

DATABASE_URL=postgresql+asyncpg://agentauth:YOUR_DB_PASSWORD@localhost:5432/agentauth
REDIS_URL=redis://localhost:6379/0

SECRET_KEY=your-secret-key-here          # generate: openssl rand -hex 32
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

API_V1_PREFIX=/api/v1
CORS_ORIGINS=["https://yourdomain.com"]

ADMIN_API_KEY=your-admin-api-key-here    # generate: openssl rand -hex 32

POSTGRES_DB=agentauth
POSTGRES_USER=agentauth
POSTGRES_PASSWORD=YOUR_DB_PASSWORD       # must match DATABASE_URL
```

**Create the initial slot state file:**

```bash
echo "blue" > /opt/agentauth/.active-slot
```

---

## 6. First Deployment Walkthrough

**Start infrastructure services only:**

```bash
cd /opt/agentauth
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

**Required GitHub Secrets** — add in *Settings > Secrets and variables > Actions*:

| Secret | Description |
|---|---|
| `DEPLOY_HOST` | IP address or hostname of the VPS |
| `DEPLOY_USER` | SSH username (e.g. `deploy`) |
| `DEPLOY_SSH_KEY` | Private SSH key (PEM format) |
| `DEPLOY_PATH` | Absolute project path on the VPS (e.g. `/opt/agentauth`) |

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
cat /opt/agentauth/.active-slot

# Confirm the Nginx symlink target
ls -la /etc/nginx/conf.d/agentauth-active.conf
```

**Manual emergency slot switch** (if the deploy script is unavailable):

```bash
# Switch to green manually
sudo ln -sf /etc/nginx/conf.d/agentauth-green.conf /etc/nginx/conf.d/agentauth-active.conf
sudo systemctl reload nginx
echo "green" > /opt/agentauth/.active-slot
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

## 10. Troubleshooting

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
cat /opt/agentauth/.active-slot
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

Ensure all four GitHub Secrets are configured in *Settings > Secrets and variables > Actions*: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, `DEPLOY_PATH`.

**Migrations fail during deploy**

Run migrations manually against the target slot:

```bash
docker compose -f docker-compose.prod.yml run --rm app-blue uv run alembic upgrade head
```
