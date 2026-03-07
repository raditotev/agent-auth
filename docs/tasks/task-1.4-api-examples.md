# Task 1.4 - Credential API Examples

## Quick Reference for Credential Management

### 1. Create a New API Key

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
    "type": "api_key",
    "scopes": ["files.read", "files.write"],
    "metadata": {
      "environment": "production",
      "ip_allowlist": ["192.168.1.0/24"]
    }
  }'
```

**Response (201 Created):**
```json
{
  "credential": {
    "id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
    "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
    "type": "api_key",
    "prefix": "EnQpJjim",
    "scopes": ["files.read", "files.write"],
    "expires_at": null,
    "last_used_at": null,
    "last_rotated_at": null,
    "revoked_at": null,
    "metadata": {
      "environment": "production",
      "ip_allowlist": ["192.168.1.0/24"]
    },
    "created_at": "2026-03-06T13:43:28.123456Z",
    "updated_at": "2026-03-06T13:43:28.123456Z",
    "is_valid": true
  },
  "raw_key": "EnQpJjimXyZ123abc456def789ghi01",
  "message": "Save this API key securely - it will never be shown again"
}
```

⚠️ **IMPORTANT:** Save the `raw_key` immediately! It will never be displayed again.

---

### 2. Create Bootstrap Credential (for Self-Registration)

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
    "type": "bootstrap",
    "scopes": ["agent.register"],
    "expires_at": "2026-03-07T13:43:28.123456Z"
  }'
```

**Response:**
```json
{
  "credential": {
    "id": "069aada0-1234-7b4d-8000-abc123def456",
    "type": "bootstrap",
    "prefix": "BtStRp12",
    "scopes": ["agent.register"],
    "expires_at": "2026-03-07T13:43:28.123456Z",
    "is_valid": true,
    ...
  },
  "raw_key": "BtStRp12abc123def456ghi789jkl012"
}
```

---

### 3. List All Credentials

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/credentials?limit=50&offset=0"
```

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
      "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
      "type": "api_key",
      "prefix": "EnQpJjim",
      "scopes": ["files.read", "files.write"],
      "is_valid": true,
      ...
    },
    {
      "id": "069aada0-1234-7b4d-8000-abc123def456",
      "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
      "type": "bootstrap",
      "prefix": "BtStRp12",
      "scopes": ["agent.register"],
      "is_valid": true,
      ...
    }
  ],
  "meta": {
    "total": 2,
    "limit": 50,
    "offset": 0,
    "agent_id": null
  }
}
```

Note: Keys are **masked** - only prefix is shown.

---

### 4. List Credentials for Specific Agent

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/credentials?agent_id=069aada0-0eea-7f86-8000-7ea4978e9736"
```

**Response:** Same as above, but filtered to one agent.

---

### 5. Get Credential Details

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/credentials/069aada0-0fc7-7b4d-8000-5f9dc3605837"
```

**Response (200 OK):**
```json
{
  "data": {
    "id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
    "agent_id": "069aada0-0eea-7f86-8000-7ea4978e9736",
    "type": "api_key",
    "prefix": "EnQpJjim",
    "scopes": ["files.read", "files.write"],
    "expires_at": null,
    "last_used_at": "2026-03-06T14:00:00.123456Z",
    "last_rotated_at": null,
    "revoked_at": null,
    "metadata": {
      "environment": "production"
    },
    "created_at": "2026-03-06T13:43:28.123456Z",
    "updated_at": "2026-03-06T14:00:00.123456Z",
    "is_valid": true
  },
  "meta": {
    "credential_id": "069aada0-0fc7-7b4d-8000-5f9dc3605837"
  }
}
```

---

### 6. Rotate a Credential

**Request:**
```bash
curl -X POST "http://localhost:8000/api/v1/credentials/069aada0-0fc7-7b4d-8000-5f9dc3605837/rotate"
```

**Response (200 OK):**
```json
{
  "old_credential": {
    "id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
    "prefix": "EnQpJjim",
    "revoked_at": "2026-03-06T15:00:00.123456Z",
    "last_rotated_at": "2026-03-06T15:00:00.123456Z",
    "is_valid": false,
    ...
  },
  "new_credential": {
    "id": "069aada0-5678-7b4d-8000-xyz789abc012",
    "prefix": "Nw5tRk9y",
    "revoked_at": null,
    "is_valid": true,
    ...
  },
  "raw_key": "Nw5tRk9yAbc123def456ghi789jkl01",
  "message": "Old key revoked. Save new key securely - it will never be shown again"
}
```

⚠️ **IMPORTANT:**
- Old key is immediately revoked
- New key is returned ONCE - save it now!

---

### 7. Revoke a Credential

**Request:**
```bash
curl -X DELETE "http://localhost:8000/api/v1/credentials/069aada0-0fc7-7b4d-8000-5f9dc3605837"
```

**Response (200 OK):**
```json
{
  "data": {
    "id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
    "prefix": "EnQpJjim",
    "revoked_at": "2026-03-06T16:00:00.123456Z",
    "is_valid": false,
    ...
  },
  "meta": {
    "credential_id": "069aada0-0fc7-7b4d-8000-5f9dc3605837",
    "message": "Credential revoked successfully"
  }
}
```

⚠️ **This action is irreversible!**

---

### 8. Include Revoked Credentials in List

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/credentials?include_revoked=true"
```

**Response:** Includes both active and revoked credentials.

---

## Error Responses

### 404 - Credential Not Found
```json
{
  "detail": "Credential not found: 069aada0-0000-0000-0000-000000000000"
}
```

### 400 - Already Revoked
```json
{
  "detail": "Credential already revoked"
}
```

### 500 - Server Error
```json
{
  "detail": "Failed to create credential"
}
```

---

## Security Notes

1. **Raw keys are never stored** - only argon2 hash
2. **Raw keys shown exactly once** - at creation or rotation
3. **Keys are 32 bytes, base62-encoded** - URL-safe
4. **Argon2id hashing** - industry standard, slow to crack
5. **Audit events** - all operations are logged
6. **Prefix identification** - first 8 chars for logs (safe)
7. **Scopes** - fine-grained permission control
8. **Expiration** - optional time-limited credentials
9. **Revocation** - immediate invalidation
10. **Rotation** - atomic old→new transition

---

## Audit Events

Every credential operation creates an audit event:

- `credential.created` - New credential issued
- `credential.revoked` - Credential invalidated
- `credential.rotated` - Old credential replaced with new

Query audit events: (Future endpoint in Phase 4)
```bash
curl -X GET "http://localhost:8000/api/v1/audit/events?event_type=credential.created"
```

---

## Next Steps

After creating a credential, use it to authenticate requests:

```bash
curl -X GET "http://localhost:8000/api/v1/agents" \
  -H "X-Agent-Key: EnQpJjimXyZ123abc456def789ghi01"
```

(API key authentication middleware will be implemented in Task 1.6)
