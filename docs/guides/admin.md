# Admin Endpoints (Platform Operators)

Admin endpoints are for **platform operators** — the people who deploy and run AgentAuth — not for root agents or tenants. They use a separate API key (`ADMIN_API_KEY`) and the `X-Admin-Key` header.

Root agents cannot access admin endpoints. Only the configured admin key grants access.

## Setup

Set `ADMIN_API_KEY` in your environment (or `.env`):

```bash
export ADMIN_API_KEY="your-secure-admin-key"
```

Generate a strong key (e.g. `openssl rand -hex 32`).

## Endpoints

### GET /api/v1/stats

Returns system-wide statistics for dashboards and monitoring:

```bash
curl http://localhost:8000/api/v1/stats \
  -H "X-Admin-Key: your-admin-api-key"
```

Response:

```json
{
  "data": {
    "agents": 42,
    "credentials": 128,
    "tokens_issued": 15420
  },
  "meta": {}
}
```

### GET /api/v1/audit/events

Query the audit log with filters and cursor-based pagination:

```bash
curl "http://localhost:8000/api/v1/audit/events?limit=50" \
  -H "X-Admin-Key: your-admin-api-key"
```

Supports `event_type`, `actor_id`, `target_id`, `outcome`, `from_date`, `to_date`, `after` (cursor), `limit`, and `export=true` for JSONL.

## Authentication

- **Header**: `X-Admin-Key: <your ADMIN_API_KEY value>`
- **401**: Missing or invalid key
- **503**: `ADMIN_API_KEY` not configured (admin endpoints disabled)

## Security

- Store `ADMIN_API_KEY` securely (secrets manager, not in code)
- Rotate periodically
- Use different keys per environment (dev/staging/prod)
