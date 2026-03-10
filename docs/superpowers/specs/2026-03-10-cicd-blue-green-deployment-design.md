# CI/CD and Blue/Green Deployment Design

## Context

AgentAuth needs a CI/CD pipeline and production deployment strategy for a single Hetzner VPS. The project uses FastAPI, PostgreSQL, Redis, and Celery. Cloudflare Tunnel provides external access; Nginx handles local blue/green routing.

## Decisions

- **CI:** GitHub Actions (lint/typecheck -> test -> deploy on main)
- **Container images:** Built on the VPS from source (no registry)
- **Reverse proxy:** Nginx on VPS for blue/green upstream switching
- **External access:** Cloudflare Tunnel -> Nginx port 80
- **Database/Redis:** Docker containers on the same VPS with persistent volumes
- **Deploy trigger:** Auto-deploy on push/merge to main (after CI passes)
- **Deploy mechanism:** SSH from GitHub Actions into VPS, execute deploy script
- **Blue/green:** Docker Compose profiles; only one app slot active at a time

## Architecture

```
GitHub (push to main)
  -> GitHub Actions CI (lint -> test -> deploy)
    -> SSH into Hetzner VPS
      -> scripts/deploy.sh
        -> git pull, build image, migrate DB
        -> start new slot, health check
        -> swap nginx upstream, stop old slot

Cloudflare Tunnel -> Nginx (:80) -> active slot (blue :8001 or green :8002)
                                  -> Postgres, Redis, Celery (shared, always running)
```

## CI Pipeline

**File:** `.github/workflows/ci.yml`

Three jobs:

1. **lint-and-typecheck** - `ruff check`, `ruff format --check`, `mypy`
2. **test** - Postgres + Redis service containers, `alembic upgrade head`, `pytest -x -q`
3. **deploy** - Runs only on main after lint+test pass. SSHes into VPS and runs `scripts/deploy.sh`

**GitHub Secrets:** `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, `DEPLOY_PATH`

## Production Docker Compose

**File:** `docker-compose.prod.yml`

Services:
- **postgres** - PostgreSQL 16, persistent volume, healthcheck, restart always
- **redis** - Redis 7, persistent volume (AOF), healthcheck, restart always
- **app-blue** - App container, profile `blue`, port 8001:8000, depends on postgres+redis
- **app-green** - App container, profile `green`, port 8002:8000, depends on postgres+redis
- **celery-worker** - Celery worker, restart always
- **celery-beat** - Celery beat scheduler, restart always

Blue and green use Docker Compose profiles so only one runs at a time.

## Nginx Configuration

Nginx installed via apt on the VPS (not containerized).

- `/etc/nginx/sites-available/agentauth` - Main site config, includes active upstream
- `/etc/nginx/conf.d/agentauth-blue.conf` - Upstream to port 8001
- `/etc/nginx/conf.d/agentauth-green.conf` - Upstream to port 8002
- `/etc/nginx/conf.d/agentauth-active.conf` - Symlink to whichever is live

Swap = change symlink + `nginx -s reload` (zero-downtime).

Config files stored in repo under `nginx/` for reference.

## Deploy Script

**File:** `scripts/deploy.sh`

Steps:
1. Read current slot from `/opt/agentauth/.active-slot` (default: none/blue)
2. Set target = opposite slot
3. `git pull origin main`
4. Build target image
5. Run database migrations via target container
6. Start target container
7. Poll health endpoint (max 30s)
8. If healthy: swap nginx symlink, reload nginx, update state file, stop old slot, prune images
9. If unhealthy: stop target, exit with error (old slot unaffected)

**Rollback:** `scripts/deploy.sh rollback` - starts previous slot, swaps nginx back, stops current.

## Documentation

**File:** `docs/deployment.md`

Sections:
1. Prerequisites (VPS specs, software)
2. Initial server setup (SSH, firewall, deploy user)
3. Cloudflare Tunnel setup
4. Nginx configuration
5. Application setup (clone, env, initial DB)
6. First deployment walkthrough
7. CI/CD setup (GitHub Secrets)
8. Blue/green deployment (how it works, verify, rollback)
9. Monitoring and maintenance (health checks, logs, backups, cleanup)
10. Troubleshooting

## Files to Create

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | CI pipeline |
| `docker-compose.prod.yml` | Production services |
| `nginx/agentauth.conf` | Main Nginx site config |
| `nginx/blue.conf` | Blue upstream |
| `nginx/green.conf` | Green upstream |
| `scripts/deploy.sh` | Deploy + rollback script |
| `docs/deployment.md` | Production deployment guide |

## No Changes to Existing Code

The Dockerfile, health/readiness endpoints, and application config already support this deployment model.
