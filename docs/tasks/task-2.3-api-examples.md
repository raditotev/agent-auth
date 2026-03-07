# Task 2.3: Client Credentials Grant - API Examples

This document provides practical examples for using the client_credentials grant type.

## Table of Contents

1. [Basic Authentication](#basic-authentication)
2. [Scope Management](#scope-management)
3. [Error Scenarios](#error-scenarios)
4. [Token Validation](#token-validation)
5. [Complete Workflow](#complete-workflow)

---

## Basic Authentication

### Example 1: Authenticate with API Key

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF"
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJodHRwczovL2FnZW50YXV0aC5leGFtcGxlLmNvbSIsInN1YiI6IjA2OWFiMWI3LTNlMjQtNzY2NS04MDAwLTMxZGY1MTczY2RlMyIsImF1ZCI6Imh0dHBzOi8vYWdlbnRhdXRoLmV4YW1wbGUuY29tIiwiZXhwIjoxNzA5NzQwODAwLCJpYXQiOjE3MDk3Mzk5MDAsImp0aSI6InVuaXF1ZS10b2tlbi1pZCIsInNjb3BlcyI6WyJmaWxlcy5yZWFkIiwiZmlsZXMud3JpdGUiLCJlbWFpbC5zZW5kIl0sImFnZW50X3R5cGUiOiJvcmNoZXN0cmF0b3IiLCJ0cnVzdF9sZXZlbCI6InJvb3QiLCJwYXJlbnRfYWdlbnRfaWQiOm51bGwsImRlbGVnYXRpb25fY2hhaW4iOm51bGwsInRva2VuX3R5cGUiOiJhY2Nlc3MifQ.signature",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJodHRwczovL2FnZW50YXV0aC5leGFtcGxlLmNvbSIsInN1YiI6IjA2OWFiMWI3LTNlMjQtNzY2NS04MDAwLTMxZGY1MTczY2RlMyIsImF1ZCI6Imh0dHBzOi8vYWdlbnRhdXRoLmV4YW1wbGUuY29tIiwiZXhwIjoxNzEwMzQ0NzAwLCJpYXQiOjE3MDk3Mzk5MDAsImp0aSI6InJlZnJlc2gtdG9rZW4taWQiLCJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImFnZW50X3R5cGUiOiJvcmNoZXN0cmF0b3IiLCJ0cnVzdF9sZXZlbCI6InJvb3QiLCJwYXJlbnRfYWdlbnRfaWQiOm51bGx9.signature",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "files.read files.write email.send",
  "issued_at": "2026-03-06T18:05:00Z",
  "expires_at": "2026-03-06T18:20:00Z"
}
```

### Example 2: Authenticate with Client ID + Secret

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=069ab1b7-3e24-7665-8000-31df5173cde3" \
  -d "client_secret=J4984rmYPQRSTUVWXYZ987654321"
```

**Response:** Same as Example 1

---

## Scope Management

### Example 3: Request Specific Scopes (Subset)

**Scenario:** Credential has `["files.read", "files.write", "email.send"]` but agent only needs file read access.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF" \
  -d "scope=files.read"
```

**Response (200 OK):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "files.read",
  "issued_at": "2026-03-06T18:05:00Z",
  "expires_at": "2026-03-06T18:20:00Z"
}
```

### Example 4: Request Multiple Scopes

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF" \
  -d "scope=files.read files.write"
```

**Response (200 OK):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "files.read files.write",
  "issued_at": "2026-03-06T18:05:00Z",
  "expires_at": "2026-03-06T18:20:00Z"
}
```

### Example 5: Omit Scope to Get All Allowed Scopes

**Scenario:** When no scope is specified, all credential scopes are granted.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF"
```

**Response (200 OK):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "files.read files.write email.send",
  "issued_at": "2026-03-06T18:05:00Z",
  "expires_at": "2026-03-06T18:20:00Z"
}
```

---

## Error Scenarios

### Example 6: Invalid Credential

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=INVALID_KEY_12345"
```

**Response (401 Unauthorized):**
```json
{
  "detail": {
    "error": "invalid_client",
    "error_description": "Invalid client credentials"
  }
}
```

### Example 7: Scope Escalation Attempt

**Scenario:** Credential has `["files.read"]` but agent requests `["files.read", "admin.access"]`.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF" \
  -d "scope=files.read admin.access"
```

**Response (400 Bad Request):**
```json
{
  "detail": {
    "error": "invalid_scope",
    "error_description": "Requested scopes exceed credential's allowed scopes"
  }
}
```

### Example 8: Missing Required Parameter

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials"
```

**Response (400 Bad Request):**
```json
{
  "detail": {
    "error": "invalid_request",
    "error_description": "client_secret is required"
  }
}
```

### Example 9: Unsupported Grant Type

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=abc123"
```

**Response (400 Bad Request):**
```json
{
  "detail": {
    "error": "unsupported_grant_type",
    "error_description": "Grant type 'authorization_code' is not supported"
  }
}
```

### Example 10: Inactive/Suspended Agent

**Scenario:** Agent has been suspended or deactivated.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF"
```

**Response (401 Unauthorized):**
```json
{
  "detail": {
    "error": "invalid_client",
    "error_description": "Agent is not active"
  }
}
```

### Example 11: Revoked Credential

**Scenario:** API key has been revoked.

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=REVOKED_KEY_ABCDEF"
```

**Response (401 Unauthorized):**
```json
{
  "detail": {
    "error": "invalid_client",
    "error_description": "Invalid client credentials"
  }
}
```

---

## Token Validation

### Example 12: Decode Access Token (Unverified)

**Using jwt.io or JWT libraries:**

```python
import jwt

access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9..."

# Decode without verification (for inspection only)
decoded = jwt.decode(access_token, options={"verify_signature": False})

print(decoded)
```

**Output:**
```json
{
  "iss": "https://agentauth.example.com",
  "sub": "069ab1b7-3e24-7665-8000-31df5173cde3",
  "aud": "https://agentauth.example.com",
  "exp": 1709740800,
  "iat": 1709739900,
  "jti": "unique-token-id",
  "scopes": ["files.read", "files.write"],
  "agent_type": "orchestrator",
  "trust_level": "root",
  "parent_agent_id": null,
  "delegation_chain": null,
  "token_type": "access"
}
```

### Example 13: Verify Access Token Signature

**Using JWKS endpoint:**

```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 1. Get JWKS
jwks_response = requests.get("http://localhost:8000/api/v1/auth/jwks")
jwks = jwks_response.json()

# 2. Extract key ID from token header
token_header = jwt.get_unverified_header(access_token)
kid = token_header["kid"]

# 3. Find matching public key in JWKS
public_key_jwk = next(k for k in jwks["keys"] if k["kid"] == kid)

# 4. Verify signature
decoded = jwt.decode(
    access_token,
    public_key_jwk,
    algorithms=["RS256"],
    audience="https://agentauth.example.com",
    issuer="https://agentauth.example.com"
)

print("Token is valid!")
print(f"Agent ID: {decoded['sub']}")
print(f"Scopes: {decoded['scopes']}")
```

---

## Complete Workflow

### Example 14: Full Agent Authentication Flow

**Step 1: Create Agent (one-time setup)**
```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: BOOTSTRAP_KEY" \
  -d '{
    "name": "my-ai-agent",
    "agent_type": "autonomous",
    "description": "My AI agent for file operations"
  }'
```

**Response:**
```json
{
  "data": {
    "id": "069ab1b7-3e24-7665-8000-31df5173cde3",
    "name": "my-ai-agent",
    "agent_type": "autonomous",
    "trust_level": "delegated",
    "status": "active"
  }
}
```

**Step 2: Create API Key (one-time setup)**
```bash
curl -X POST http://localhost:8000/api/v1/credentials \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: BOOTSTRAP_KEY" \
  -d '{
    "agent_id": "069ab1b7-3e24-7665-8000-31df5173cde3",
    "type": "api_key",
    "scopes": ["files.read", "files.write"]
  }'
```

**Response:**
```json
{
  "data": {
    "id": "069ab1b7-4567-7890-8000-abcdef123456",
    "prefix": "A7sjbCLc",
    "type": "api_key",
    "scopes": ["files.read", "files.write"],
    "api_key": "A7sjbCLcXYZ123456789ABCDEF"
  },
  "meta": {
    "warning": "Save this API key - it will not be shown again!"
  }
}
```

**Step 3: Authenticate and Get Token**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_secret=A7sjbCLcXYZ123456789ABCDEF" \
  -d "scope=files.read files.write"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "files.read files.write",
  "issued_at": "2026-03-06T18:05:00Z",
  "expires_at": "2026-03-06T18:20:00Z"
}
```

**Step 4: Use Access Token for API Calls**
```bash
curl -X GET http://localhost:8000/api/v1/files \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

**Step 5: Refresh Token When Expired (Future: Task 2.6)**
```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=eyJhbGciOiJSUzI1NiIs..."
```

---

## HTTPie Examples

For those who prefer HTTPie over curl:

### Basic Authentication
```bash
http --form POST localhost:8000/api/v1/auth/token \
  grant_type=client_credentials \
  client_secret=A7sjbCLcXYZ123456789ABCDEF
```

### With Specific Scopes
```bash
http --form POST localhost:8000/api/v1/auth/token \
  grant_type=client_credentials \
  client_secret=A7sjbCLcXYZ123456789ABCDEF \
  scope='files.read files.write'
```

---

## Python SDK Usage (Future)

Once the Python SDK is implemented (Task 4.1), the flow will be much simpler:

```python
from agentauth_sdk import AgentAuthClient

# Initialize client with API key
client = AgentAuthClient(
    base_url="https://agentauth.example.com",
    api_key="A7sjbCLcXYZ123456789ABCDEF"
)

# Get tokens (auto-handled)
tokens = client.authenticate(scopes=["files.read", "files.write"])

# Use tokens for API calls (auto-refresh)
response = client.get("/api/v1/files")

# Token refresh is automatic
# Access token is automatically included in all requests
```

---

## Notes

1. **Token Lifetime**: Access tokens expire in 15 minutes by default, refresh tokens in 7 days
2. **Scope Format**: Space-separated string (OAuth 2.0 standard)
3. **Token Storage**: Store refresh tokens securely; access tokens can be ephemeral
4. **Error Handling**: Always check for 401/400 status codes and handle re-authentication
5. **Rate Limiting**: Future task will add rate limits to prevent abuse
