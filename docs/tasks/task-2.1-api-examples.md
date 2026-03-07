# Task 2.1 - JWK Management API Examples

## JWKS Endpoint Usage

### Get Public Keys (JWKS)

Retrieve all valid public keys for token verification.

```bash
curl http://localhost:8000/api/v1/auth/jwks
```

**Response:**
```json
{
  "keys": [
    {
      "kid": "a1b2c3d4e5f6g7h8i9j0",
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "n": "xGOr-H7A8Nk3z...",
      "e": "AQAB"
    },
    {
      "kid": "k1l2m3n4o5p6q7r8s9t0",
      "alg": "ES256",
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "x": "WKn-ZIGeVCmXy...",
      "y": "6Y_rZfEyP8..."
    }
  ]
}
```

## Python SDK Usage

### Generating Keys

```python
from agentauth.services.crypto import CryptoService
from agentauth.core.database import get_session_maker

# Create session
session_maker = get_session_maker()
async with session_maker() as session:
    crypto_service = CryptoService(session)

    # Generate RSA key
    rsa_key = await crypto_service.generate_rsa_key_pair(
        key_size=2048,
        expiration_days=90,
    )
    session.add(rsa_key)

    # Generate ECDSA key
    ec_key = await crypto_service.generate_ecdsa_key_pair(
        expiration_days=90,
    )
    session.add(ec_key)

    await session.commit()

    print(f"RSA Key ID: {rsa_key.key_id}")
    print(f"EC Key ID: {ec_key.key_id}")
```

### Getting Active Signing Key

```python
from agentauth.models.signing_key import KeyAlgorithm

async with session_maker() as session:
    crypto_service = CryptoService(session)

    # Get active RSA key
    rsa_key = await crypto_service.get_active_signing_key(KeyAlgorithm.RS256)

    if rsa_key:
        print(f"Active RSA key: {rsa_key.key_id}")
        print(f"Expires: {rsa_key.expiration_date}")
```

### Exporting JWKS

```python
async with session_maker() as session:
    crypto_service = CryptoService(session)

    # Export all valid public keys
    jwks = await crypto_service.export_jwks()

    print(f"JWKS has {len(jwks['keys'])} keys")
    for key in jwks['keys']:
        print(f"  - {key['kid']} ({key['alg']})")
```

### Manual Key Rotation

```python
async with session_maker() as session:
    crypto_service = CryptoService(session)

    # Rotate keys
    result = await crypto_service.rotate_keys()

    print(f"Expired keys: {result['expired']}")
    print(f"Created keys: {result['created']}")
```

## Celery Task Usage

### Running Key Rotation Task

```bash
# Start Celery worker
celery -A agentauth.tasks.key_rotation worker --loglevel=info

# Start Celery beat (scheduler)
celery -A agentauth.tasks.key_rotation beat --loglevel=info

# Or run both together
celery -A agentauth.tasks.key_rotation worker --beat --loglevel=info
```

### Manual Task Invocation

```python
from agentauth.tasks.key_rotation import rotate_signing_keys

# Call task synchronously (for testing)
result = rotate_signing_keys()
print(result)
# {'expired': ['key_id_1'], 'created': ['key_id_2', 'key_id_3']}

# Call task asynchronously
task = rotate_signing_keys.delay()
result = task.get(timeout=60)
```

## Database Queries

### Get All Active Keys

```sql
SELECT key_id, algorithm, status, activation_date, expiration_date
FROM signing_keys
WHERE status = 'ACTIVE'
  AND activation_date <= NOW()
  AND expiration_date > NOW()
  AND revoked_at IS NULL
ORDER BY activation_date DESC;
```

### Get Keys for JWKS

```sql
SELECT key_id, algorithm, public_key_pem
FROM signing_keys
WHERE status IN ('ACTIVE', 'EXPIRED')
  AND revoked_at IS NULL
ORDER BY activation_date DESC;
```

### Find Expired Keys

```sql
SELECT key_id, algorithm, expiration_date
FROM signing_keys
WHERE status = 'ACTIVE'
  AND expiration_date <= NOW();
```

## Testing Examples

### Test Key Generation

```python
import pytest
from agentauth.services.crypto import CryptoService

@pytest.mark.asyncio
async def test_generate_keys(db_session):
    crypto_service = CryptoService(db_session)

    # Generate both key types
    rsa_key = await crypto_service.generate_rsa_key_pair()
    ec_key = await crypto_service.generate_ecdsa_key_pair()

    assert rsa_key.algorithm == KeyAlgorithm.RS256
    assert ec_key.algorithm == KeyAlgorithm.ES256

    assert rsa_key.is_active()
    assert ec_key.is_active()
```

### Test JWKS Endpoint

```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_jwks_endpoint(client: AsyncClient, db_session):
    # Setup: create keys
    crypto_service = CryptoService(db_session)
    key = await crypto_service.generate_rsa_key_pair()
    db_session.add(key)
    await db_session.commit()

    # Test: call endpoint
    response = await client.get("/api/v1/auth/jwks")

    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == key.key_id
```

## Production Deployment

### Environment Variables

```bash
# Redis for Celery
REDIS_URL=redis://localhost:6379/0

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/agentauth

# Celery config
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

### Docker Compose

```yaml
services:
  celery-worker:
    build: .
    command: celery -A agentauth.tasks.key_rotation worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@db/agentauth
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  celery-beat:
    build: .
    command: celery -A agentauth.tasks.key_rotation beat --loglevel=info
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@db/agentauth
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
```

### Key Rotation Schedule

Default schedule: **Daily at midnight UTC**

To customize:
```python
celery_app.conf.beat_schedule = {
    "rotate-signing-keys": {
        "task": "agentauth.rotate_signing_keys",
        "schedule": 3600.0,  # Every hour
    },
}
```

## Security Best Practices

### 1. Secure Private Key Storage

**Development:**
```python
# Keys stored unencrypted in database
# Acceptable for development only
```

**Production:**
```python
# Option 1: Database-level encryption
# Enable PostgreSQL encryption at rest

# Option 2: Application-level encryption
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

encrypted_pem = cipher.encrypt(private_key_pem.encode())
# Store encrypted_pem in database

# Option 3: Hardware Security Module (HSM)
# Use AWS KMS, Azure Key Vault, or Google Cloud KMS
```

### 2. Key Rotation Policy

Recommended: **30 days active + 60 days grace period**

```python
# Generate new key every 30 days
expiration_days = 90  # Total lifetime

# This ensures:
# - Fresh keys used for signing
# - Old tokens can still be verified
# - No service disruption during rotation
```

### 3. Revocation

Immediately revoke compromised keys:

```python
async with session_maker() as session:
    stmt = select(SigningKey).where(SigningKey.key_id == "compromised_key_id")
    result = await session.execute(stmt)
    key = result.scalar_one_or_none()

    if key:
        key.revoke()
        await session.commit()

        # Key immediately removed from JWKS
        # All tokens signed with this key become invalid
```

### 4. Monitoring

Monitor key lifecycle:

```python
import structlog
logger = structlog.get_logger()

# Log key operations
logger.info("key_generated", key_id=key.key_id, algorithm=key.algorithm)
logger.warning("key_expiring_soon", key_id=key.key_id, expires_in_days=7)
logger.error("key_rotation_failed", error=str(e))
```

## Troubleshooting

### No Active Keys

```python
# Symptom: Token signing fails
# Solution: Run key rotation manually

from agentauth.services.crypto import CryptoService
from agentauth.core.database import get_session_maker

async def fix_no_active_keys():
    session_maker = get_session_maker()
    async with session_maker() as session:
        crypto_service = CryptoService(session)
        result = await crypto_service.rotate_keys()
        print(f"Created keys: {result['created']}")
```

### JWKS Returns Empty

```python
# Symptom: JWKS endpoint returns {"keys": []}
# Cause: All keys revoked or none generated
# Solution: Generate new keys

async with session_maker() as session:
    crypto_service = CryptoService(session)

    # Generate both key types
    rsa = await crypto_service.generate_rsa_key_pair()
    ec = await crypto_service.generate_ecdsa_key_pair()

    session.add(rsa)
    session.add(ec)
    await session.commit()
```

### Celery Task Not Running

```bash
# Check Celery worker is running
celery -A agentauth.tasks.key_rotation inspect active

# Check Celery beat schedule
celery -A agentauth.tasks.key_rotation inspect scheduled

# Check Redis connection
redis-cli ping
```

## Performance Considerations

### JWKS Caching

Recommended: Cache JWKS responses for 1 hour

```python
# In production, add caching middleware
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache

@router.get("/auth/jwks")
@cache(expire=3600)  # 1 hour
async def get_jwks():
    # ...
```

### Database Indexes

Ensure indexes exist for performance:

```sql
-- Already created by migration
CREATE INDEX ix_signing_keys_key_id ON signing_keys(key_id);
CREATE INDEX ix_signing_keys_algorithm ON signing_keys(algorithm);
CREATE INDEX ix_signing_keys_status ON signing_keys(status);
CREATE INDEX ix_signing_keys_activation_date ON signing_keys(activation_date);
CREATE INDEX ix_signing_keys_expiration_date ON signing_keys(expiration_date);
```

### Key Lookup Optimization

```python
# Use SQLAlchemy query optimization
stmt = (
    select(SigningKey)
    .where(SigningKey.status == KeyStatus.ACTIVE)
    .where(SigningKey.algorithm == algorithm)
    .order_by(SigningKey.activation_date.desc())
    .limit(1)
    .options(selectinload(SigningKey.relationships))  # If needed
)
```
