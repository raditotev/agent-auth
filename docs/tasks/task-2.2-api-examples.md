# Task 2.2: Token Service API Examples

This document provides practical examples of using the Token Service for minting, validating, and introspecting JWT tokens.

---

## Table of Contents

1. [Token Minting Examples](#token-minting-examples)
2. [Token Validation Examples](#token-validation-examples)
3. [Token Introspection Examples](#token-introspection-examples)
4. [Advanced Use Cases](#advanced-use-cases)
5. [Error Handling](#error-handling)

---

## Token Minting Examples

### Basic Access Token

Mint a simple access token for a root agent:

```python
from agentauth.services.token import TokenService
from agentauth.models.signing_key import KeyAlgorithm

# Initialize service
token_service = TokenService(db_session)

# Mint basic access token
response = await token_service.mint_token(
    agent=root_agent,
    token_type="access",
)

print(f"Access Token: {response.access_token}")
print(f"Refresh Token: {response.refresh_token}")
print(f"Expires in: {response.expires_in} seconds")
print(f"Expires at: {response.expires_at}")
```

**Response Structure**:
```python
TokenResponse(
    access_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9...",
    refresh_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9...",
    token_type="Bearer",
    expires_in=900,  # 15 minutes in seconds
    scope=None,
    issued_at=datetime(2026, 3, 6, 18, 0, 0),
    expires_at=datetime(2026, 3, 6, 18, 15, 0)
)
```

---

### Token with Scopes

Mint a token with specific permission scopes:

```python
scopes = [
    "files.read",
    "files.write",
    "email.send",
    "calendar.read"
]

response = await token_service.mint_token(
    agent=root_agent,
    scopes=scopes,
    audience="https://api.example.com",
)

print(f"Granted scopes: {response.scope}")
# Output: "files.read files.write email.send calendar.read"
```

**Token Claims**:
```json
{
  "iss": "https://agentauth.example.com",
  "sub": "069ab193-753d-7a25-8000-61fea5f0eb56",
  "aud": "https://api.example.com",
  "exp": 1772821691,
  "iat": 1772820791,
  "jti": "unique-token-id",
  "scopes": ["files.read", "files.write", "email.send", "calendar.read"],
  "agent_type": "orchestrator",
  "trust_level": "root",
  "parent_agent_id": null,
  "delegation_chain": null,
  "token_type": "access"
}
```

---

### Token for Child Agent with Delegation Chain

Mint a token for a child agent with delegation tracking:

```python
# Child agent inherits from root agent
delegation_chain = [root_agent.id, child_agent.id]

response = await token_service.mint_token(
    agent=child_agent,
    scopes=["user.read", "user.write"],
    delegation_chain=delegation_chain,
)

# Decode to inspect claims
import jwt
decoded = jwt.decode(response.access_token, options={"verify_signature": False})

print(f"Agent: {decoded['sub']}")
print(f"Parent: {decoded['parent_agent_id']}")
print(f"Delegation chain: {decoded['delegation_chain']}")
```

**Output**:
```
Agent: 550e8400-e29b-41d4-a716-446655440001
Parent: 069ab193-753d-7a25-8000-61fea5f0eb56
Delegation chain: ['069ab193-753d-7a25-8000-61fea5f0eb56', '550e8400-e29b-41d4-a716-446655440001']
```

---

### Token with Custom Expiration

Mint a short-lived token for sensitive operations:

```python
# 5-minute token instead of default 15 minutes
response = await token_service.mint_token(
    agent=root_agent,
    scopes=["admin.write", "user.delete"],
    expires_in_minutes=5,
)

print(f"Token expires in: {response.expires_in} seconds")  # 300
```

---

### Refresh Token Only

Mint only a refresh token (no access token):

```python
response = await token_service.mint_token(
    agent=root_agent,
    token_type="refresh",
)

# Refresh tokens have longer expiration (7 days by default)
print(f"Refresh token expires in: {response.expires_in // 86400} days")
# Output: 7 days
```

---

### Token with ECDSA Algorithm

Use ES256 (ECDSA) instead of RS256 (RSA):

```python
from agentauth.models.signing_key import KeyAlgorithm

response = await token_service.mint_token(
    agent=root_agent,
    scopes=["api.access"],
    algorithm=KeyAlgorithm.ES256,
)

# Verify algorithm in header
header = jwt.get_unverified_header(response.access_token)
print(f"Algorithm: {header['alg']}")  # "ES256"
```

---

### Token with Multiple Audiences

Mint a token valid for multiple services:

```python
audiences = [
    "https://api.example.com",
    "https://files.example.com",
    "https://email.example.com"
]

response = await token_service.mint_token(
    agent=root_agent,
    audience=audiences,
)

decoded = jwt.decode(response.access_token, options={"verify_signature": False})
print(f"Audiences: {decoded['aud']}")
# Output: ["https://api.example.com", "https://files.example.com", "https://email.example.com"]
```

---

## Token Validation Examples

### Basic Token Validation

Validate a token's signature and expiration:

```python
validation_result = await token_service.validate_token(
    token=access_token,
)

if validation_result.valid:
    claims = validation_result.claims
    print(f"✓ Token is valid")
    print(f"  Agent ID: {claims.sub}")
    print(f"  Agent Type: {claims.agent_type}")
    print(f"  Trust Level: {claims.trust_level}")
    print(f"  Scopes: {claims.scopes}")
else:
    print(f"✗ Token is invalid: {validation_result.error}")
```

---

### Validate with Audience Check

Ensure token is intended for a specific service:

```python
validation_result = await token_service.validate_token(
    token=access_token,
    expected_audience="https://api.example.com",
)

if not validation_result.valid:
    print(f"Token validation failed: {validation_result.error}")
    if validation_result.error_detail:
        print(f"Details: {validation_result.error_detail}")
```

---

### Validate Token Type

Ensure you're validating the correct token type:

```python
# Validate access token
result = await token_service.validate_token(
    token=some_token,
    expected_token_type="access",
)

if not result.valid:
    if "token type" in result.error.lower():
        print("Wrong token type - expected access token, got refresh token")
```

---

### Extract Claims from Valid Token

Access all claims after validation:

```python
result = await token_service.validate_token(token=access_token)

if result.valid:
    claims = result.claims

    # Standard JWT claims
    print(f"Issuer: {claims.iss}")
    print(f"Subject: {claims.sub}")
    print(f"Audience: {claims.aud}")
    print(f"Expires: {claims.exp}")
    print(f"Issued At: {claims.iat}")
    print(f"JWT ID: {claims.jti}")

    # AgentAuth custom claims
    print(f"Scopes: {claims.scopes}")
    print(f"Agent Type: {claims.agent_type}")
    print(f"Trust Level: {claims.trust_level}")
    print(f"Parent Agent: {claims.parent_agent_id}")
    print(f"Delegation Chain: {claims.delegation_chain}")
    print(f"Token Type: {claims.token_type}")
```

---

### Handle Validation Errors

Different error scenarios:

```python
result = await token_service.validate_token(token=some_token)

if not result.valid:
    if "expired" in result.error.lower():
        print("Token has expired - request new token")
    elif "signature" in result.error.lower():
        print("Token signature is invalid - possible tampering")
    elif "audience" in result.error.lower():
        print("Token not intended for this service")
    elif "issuer" in result.error.lower():
        print("Token from unknown issuer")
    else:
        print(f"Token validation failed: {result.error}")
```

---

## Token Introspection Examples

### Basic Introspection (RFC 7662)

Introspect a token to check if it's active:

```python
introspection = await token_service.introspect_token(access_token)

if introspection["active"]:
    print("Token is active")
    print(f"Client ID: {introspection['client_id']}")
    print(f"Username: {introspection['username']}")
    print(f"Scope: {introspection['scope']}")
    print(f"Token Type: {introspection['token_type']}")
    print(f"Expires: {introspection['exp']}")
else:
    print("Token is not active (expired, revoked, or invalid)")
```

**Example Response (Active Token)**:
```python
{
    "active": True,
    "scope": "files.read files.write",
    "client_id": "069ab193-753d-7a25-8000-61fea5f0eb56",
    "username": "069ab193-753d-7a25-8000-61fea5f0eb56",
    "token_type": "access",
    "exp": 1772821691,
    "iat": 1772820791,
    "sub": "069ab193-753d-7a25-8000-61fea5f0eb56",
    "aud": "https://agentauth.example.com",
    "iss": "https://agentauth.example.com",
    "jti": "unique-token-id",
    "agent_type": "orchestrator",
    "trust_level": "root",
    "parent_agent_id": None
}
```

**Example Response (Inactive Token)**:
```python
{
    "active": False
}
```

---

### Check Token Expiration

Use introspection to check remaining token lifetime:

```python
from datetime import datetime, UTC

introspection = await token_service.introspect_token(access_token)

if introspection["active"]:
    exp_timestamp = introspection["exp"]
    exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=UTC)
    now = datetime.now(UTC)

    remaining = (exp_datetime - now).total_seconds()
    print(f"Token expires in {remaining:.0f} seconds")

    if remaining < 300:  # Less than 5 minutes
        print("Warning: Token expires soon, consider refreshing")
```

---

## Advanced Use Cases

### Full Token Lifecycle

Complete example from minting to validation:

```python
from agentauth.services.token import TokenService
from agentauth.services.crypto import CryptoService
from datetime import UTC, datetime

# Setup
crypto_service = CryptoService(db_session)
token_service = TokenService(db_session)

# 1. Ensure we have a signing key
signing_key = await crypto_service.get_active_signing_key(KeyAlgorithm.RS256)
if not signing_key:
    signing_key = await crypto_service.generate_rsa_key_pair(
        activation_date=datetime.now(UTC),
        expiration_days=90,
    )
    db_session.add(signing_key)
    await db_session.commit()

# 2. Mint token
token_response = await token_service.mint_token(
    agent=root_agent,
    scopes=["api.read", "api.write"],
    audience="https://api.example.com",
)

# 3. Use the token (send in request)
access_token = token_response.access_token

# 4. Validate token on receiving end
validation = await token_service.validate_token(
    token=access_token,
    expected_audience="https://api.example.com",
)

if validation.valid:
    print(f"Authenticated as agent: {validation.claims.sub}")
    print(f"With scopes: {validation.claims.scopes}")
else:
    print(f"Authentication failed: {validation.error}")
```

---

### Extract Metadata for Logging

Extract token metadata without full validation (useful for request logging):

```python
metadata = await token_service.extract_metadata(access_token)

if metadata:
    # Log request details
    logger.info(
        "API request received",
        agent_id=str(metadata.agent_id),
        agent_type=metadata.agent_type.value,
        trust_level=metadata.trust_level.value,
        scopes=metadata.scopes,
        key_id=metadata.key_id,
        algorithm=metadata.algorithm,
    )
else:
    logger.warning("Invalid token in request")
```

---

### Verify Token with Different Keys

Validate tokens signed with different keys (after key rotation):

```python
# Token 1 signed with old key
token1 = "eyJhbGc..."

# Token 2 signed with new key
token2 = "eyJhbGc..."

# Both should validate successfully
result1 = await token_service.validate_token(token1)
result2 = await token_service.validate_token(token2)

if result1.valid and result2.valid:
    print("Both tokens valid despite different signing keys")

    # Check which keys were used
    header1 = jwt.get_unverified_header(token1)
    header2 = jwt.get_unverified_header(token2)

    print(f"Token 1 key: {header1['kid']}")
    print(f"Token 2 key: {header2['kid']}")
```

---

## Error Handling

### Handle Missing Signing Key

```python
from agentauth.core.exceptions import TokenError

try:
    response = await token_service.mint_token(
        agent=root_agent,
        algorithm=KeyAlgorithm.RS256,
    )
except TokenError as e:
    if "No active signing key" in str(e):
        print("No signing key available - generate one first")
        # Generate key
        key = await crypto_service.generate_rsa_key_pair()
        db_session.add(key)
        await db_session.commit()
        # Retry
        response = await token_service.mint_token(agent=root_agent)
```

---

### Handle Invalid Token Type

```python
try:
    response = await token_service.mint_token(
        agent=root_agent,
        token_type="invalid_type",
    )
except TokenError as e:
    print(f"Invalid token type: {e}")
    # Use valid type
    response = await token_service.mint_token(
        agent=root_agent,
        token_type="access",  # or "refresh"
    )
```

---

### Comprehensive Error Handling

```python
from agentauth.core.exceptions import TokenError

async def mint_token_safe(agent, scopes=None):
    """Safely mint token with error handling."""
    try:
        response = await token_service.mint_token(
            agent=agent,
            scopes=scopes or [],
        )
        return response, None

    except TokenError as e:
        logger.error(f"Token minting failed: {e}", extra=e.detail)
        return None, str(e)

    except Exception as e:
        logger.error(f"Unexpected error minting token: {e}")
        return None, "Internal error"

# Usage
response, error = await mint_token_safe(root_agent, ["api.read"])
if error:
    print(f"Failed to mint token: {error}")
else:
    print(f"Token minted successfully: {response.access_token[:20]}...")
```

---

## Integration with FastAPI

### Dependency for Token Validation

```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def get_current_agent(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db_session: AsyncSession = Depends(get_session),
) -> Agent:
    """Validate token and return agent."""
    token = credentials.credentials
    token_service = TokenService(db_session)

    result = await token_service.validate_token(token)

    if not result.valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
        )

    # Load agent from database
    agent_id = UUID(result.claims.sub)
    agent = await db_session.get(Agent, agent_id)

    if not agent or not agent.is_active():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent not found or inactive",
        )

    return agent

# Use in endpoint
@app.get("/api/v1/protected")
async def protected_endpoint(
    agent: Agent = Depends(get_current_agent),
):
    return {"message": f"Hello, {agent.name}!"}
```

---

## Summary

The Token Service provides a complete JWT implementation for AgentAuth with:

- **Minting**: Create access and refresh tokens with custom claims
- **Validation**: Verify signatures, expiration, audience, and more
- **Introspection**: RFC 7662 compliant token introspection
- **Metadata**: Extract token info for logging without validation
- **Error Handling**: Comprehensive error messages and recovery

All operations are fully async and integrate seamlessly with the CryptoService for key management.
