"""Token service for JWT minting, validation, and management."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.config import settings
from agentauth.core.exceptions import TokenError
from agentauth.core.redis import get_redis_client
from agentauth.core.security import decrypt_secret
from agentauth.models.agent import Agent, AgentType, TrustLevel
from agentauth.models.signing_key import KeyAlgorithm, SigningKey
from agentauth.schemas.token import TokenClaims, TokenMetadata, TokenResponse, TokenValidationResult
from agentauth.services.crypto import CryptoService

logger = structlog.get_logger()


class TokenService:
    """Service for token operations including minting, validation, and introspection."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize token service."""
        self.session = session
        self.crypto_service = CryptoService(session)
        self.issuer = settings.issuer_url

    async def mint_token(
        self,
        agent: Agent,
        scopes: list[str] | None = None,
        audience: str | list[str] | None = None,
        token_type: str = "access",
        expires_in_minutes: int | None = None,
        delegation_chain: list[UUID] | None = None,
        algorithm: KeyAlgorithm = KeyAlgorithm.RS256,
    ) -> TokenResponse:
        """
        Mint a new JWT token for an agent.

        Args:
            agent: Agent to issue token for
            scopes: Permission scopes to include
            audience: Target audience(s) for the token
            token_type: Type of token ('access' or 'refresh')
            expires_in_minutes: Custom expiration time (overrides default)
            delegation_chain: Chain of parent agent IDs
            algorithm: Signing algorithm to use

        Returns:
            TokenResponse with token and metadata

        Raises:
            TokenError: If no active signing key is available
        """
        logger.info(
            "Minting token",
            agent_id=str(agent.id),
            agent_name=agent.name,
            token_type=token_type,
            algorithm=algorithm.value,
        )

        # Get active signing key
        signing_key = await self.crypto_service.get_active_signing_key(algorithm)
        if signing_key is None:
            raise TokenError(
                f"No active signing key available for algorithm {algorithm.value}",
                detail={"algorithm": algorithm.value},
            )

        # Calculate timestamps
        now = datetime.now(UTC)
        issued_at = now
        if token_type == "access":
            expires_in = expires_in_minutes or settings.access_token_expire_minutes
            expires_at = now + timedelta(minutes=expires_in)
        elif token_type == "refresh":
            expires_in = expires_in_minutes or (settings.refresh_token_expire_days * 24 * 60)
            expires_at = now + timedelta(days=settings.refresh_token_expire_days)
        else:
            raise TokenError(f"Unknown token type: {token_type}", detail={"token_type": token_type})

        # Generate unique JWT ID
        jti = self._generate_jti()

        # Build token claims
        token_scopes = scopes or []
        token_audience = audience or self.issuer

        claims: dict[str, Any] = {
            # Standard JWT claims
            "iss": self.issuer,
            "sub": str(agent.id),
            "aud": token_audience,
            "exp": int(expires_at.timestamp()),
            "iat": int(issued_at.timestamp()),
            "jti": jti,
            # Custom AgentAuth claims
            "scopes": token_scopes,
            "agent_type": agent.agent_type.value,
            "trust_level": agent.trust_level.value,
            "parent_agent_id": str(agent.parent_agent_id) if agent.parent_agent_id else None,
            "delegation_chain": [str(uid) for uid in delegation_chain]
            if delegation_chain
            else None,
            "token_type": token_type,
        }

        # Sign the token
        access_token = await self._sign_jwt(claims, signing_key)

        # Calculate expires_in for response (in seconds)
        expires_in_seconds = int((expires_at - now).total_seconds())

        # For access tokens, optionally generate a refresh token
        refresh_token = None
        refresh_jti = None
        if token_type == "access":
            # Generate refresh token with longer expiration
            refresh_jti = self._generate_jti()
            refresh_expires_at = now + timedelta(days=settings.refresh_token_expire_days)
            refresh_claims = {
                "iss": self.issuer,
                "sub": str(agent.id),
                "aud": self.issuer,  # Refresh tokens are for the issuer
                "exp": int(refresh_expires_at.timestamp()),
                "iat": int(issued_at.timestamp()),
                "jti": refresh_jti,
                "token_type": "refresh",
                "agent_type": agent.agent_type.value,
                "trust_level": agent.trust_level.value,
                "parent_agent_id": str(agent.parent_agent_id) if agent.parent_agent_id else None,
                # Carry scopes so they can be re-issued on refresh
                "scopes": token_scopes,
                # Link to access token for cascading revocation
                "access_token_jti": jti,
            }
            refresh_token = await self._sign_jwt(refresh_claims, signing_key)

            # Store the token pair relationship in Redis for cascading revocation
            redis_client = get_redis_client()
            refresh_expires_in_seconds = int((refresh_expires_at - now).total_seconds())

            # Map access JTI -> refresh JTI and vice versa
            await redis_client.set(f"token_pair:access:{jti}", refresh_jti, ex=expires_in_seconds)
            await redis_client.set(
                f"token_pair:refresh:{refresh_jti}", jti, ex=refresh_expires_in_seconds
            )

        logger.info(
            "Token minted successfully",
            agent_id=str(agent.id),
            token_type=token_type,
            jti=jti,
            expires_in=expires_in_seconds,
            key_id=signing_key.key_id,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer",
            expires_in=expires_in_seconds,
            scope=" ".join(token_scopes) if token_scopes else None,
            issued_at=issued_at,
            expires_at=expires_at,
            refresh_before=expires_at - timedelta(seconds=60),
        )

    async def _sign_jwt(self, claims: dict[str, Any], signing_key: SigningKey) -> str:
        """
        Sign JWT claims with the given signing key.

        Args:
            claims: JWT claims dictionary
            signing_key: SigningKey to use for signing

        Returns:
            Signed JWT string

        Raises:
            TokenError: If signing fails
        """
        try:
            # Decrypt private key from storage using the dedicated encryption key.
            private_pem = decrypt_secret(
                signing_key.private_key_pem, settings.effective_signing_key_encryption_key
            )
            private_key_obj = serialization.load_pem_private_key(
                private_pem.encode("utf-8"),
                password=None,
            )

            # Create JWT with key ID in header
            token = jwt.encode(
                claims,
                private_key_obj,  # type: ignore[arg-type]
                algorithm=signing_key.algorithm.value,
                headers={"kid": signing_key.key_id},
            )

            return token

        except Exception as e:
            logger.error(
                "Failed to sign JWT",
                error=str(e),
                key_id=signing_key.key_id,
                algorithm=signing_key.algorithm.value,
            )
            raise TokenError(
                "Failed to sign token",
                detail={"error": str(e), "key_id": signing_key.key_id},
            ) from e

    async def validate_token(
        self,
        token: str,
        expected_audience: str | list[str] | None = None,
        expected_token_type: str | None = None,
    ) -> TokenValidationResult:
        """
        Validate a JWT token.

        Args:
            token: JWT token string
            expected_audience: Expected audience(s) to validate
            expected_token_type: Expected token type ('access' or 'refresh')

        Returns:
            TokenValidationResult with validation status and claims
        """
        try:
            # Decode header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            key_id = unverified_header.get("kid")

            if not key_id:
                return TokenValidationResult(
                    valid=False,
                    error="Missing key ID in token header",
                )

            # Try Redis cache for signing key first, fall back to DB
            redis_client = get_redis_client()
            cache_key = f"signing_key_cache:{key_id}"
            cached_key_data = await redis_client.get_json(cache_key)

            if cached_key_data is not None:
                # Use cached key data
                public_key_pem = cached_key_data["public_key_pem"]
                algorithm_value = cached_key_data["algorithm"]
                signing_key = None  # Not needed beyond this point
            else:
                # Get signing key from database
                signing_key = await self.crypto_service.get_signing_key_by_id(key_id)

                if signing_key is None:
                    return TokenValidationResult(
                        valid=False,
                        error="Unknown signing key",
                        error_detail={"key_id": key_id},
                    )

                # Check if key is valid for verification
                if not signing_key.is_valid_for_verification():
                    return TokenValidationResult(
                        valid=False,
                        error="Signing key is not valid for verification",
                        error_detail={"key_id": key_id, "status": signing_key.status.value},
                    )

                public_key_pem = signing_key.public_key_pem
                algorithm_value = signing_key.algorithm.value

                # Cache the key for future lookups
                await redis_client.set_json(
                    cache_key,
                    {
                        "public_key_pem": public_key_pem,
                        "algorithm": algorithm_value,
                        "key_id": key_id,
                        "status": signing_key.status.value,
                    },
                    ex=600,
                )

            # Load public key
            public_key_obj = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

            # Verify and decode token
            options = {"verify_aud": expected_audience is not None}
            decoded = jwt.decode(
                token,
                public_key_obj,  # type: ignore[arg-type]
                algorithms=[algorithm_value],
                issuer=self.issuer,
                audience=expected_audience,
                options=options,  # type: ignore[arg-type]
            )

            # Validate token type if specified
            if expected_token_type:
                actual_token_type = decoded.get("token_type")
                if actual_token_type != expected_token_type:
                    return TokenValidationResult(
                        valid=False,
                        error="Invalid token type",
                        error_detail={
                            "expected": expected_token_type,
                            "actual": actual_token_type,
                        },
                    )

            # Check if token has been revoked
            jti = decoded.get("jti")
            if jti:
                revoked = await redis_client.exists(f"revoked:{jti}")
                if revoked:
                    return TokenValidationResult(
                        valid=False, claims=None, error="Token has been revoked"
                    )

            # Parse claims into TokenClaims schema
            try:
                # Convert parent_agent_id and delegation_chain back to UUIDs
                if decoded.get("parent_agent_id"):
                    decoded["parent_agent_id"] = UUID(decoded["parent_agent_id"])
                if decoded.get("delegation_chain"):
                    decoded["delegation_chain"] = [UUID(uid) for uid in decoded["delegation_chain"]]

                claims = TokenClaims(**decoded)
            except Exception as e:
                logger.warning("Failed to parse token claims", error=str(e), claims=decoded)
                return TokenValidationResult(
                    valid=False,
                    error="Invalid token claims format",
                    error_detail={"parse_error": str(e)},
                )

            logger.info(
                "Token validated successfully",
                jti=claims.jti,
                sub=claims.sub,
                token_type=claims.token_type,
            )

            return TokenValidationResult(
                valid=True,
                claims=claims,
            )

        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                valid=False,
                error="Token has expired",
            )
        except jwt.InvalidIssuerError:
            return TokenValidationResult(
                valid=False,
                error="Invalid token issuer",
            )
        except jwt.InvalidAudienceError:
            return TokenValidationResult(
                valid=False,
                error="Invalid token audience",
            )
        except jwt.InvalidSignatureError:
            return TokenValidationResult(
                valid=False,
                error="Invalid token signature",
            )
        except jwt.DecodeError as e:
            return TokenValidationResult(
                valid=False,
                error="Failed to decode token",
                error_detail={"decode_error": str(e)},
            )
        except Exception as e:
            logger.error("Unexpected error during token validation", error=str(e))
            return TokenValidationResult(
                valid=False,
                error="Token validation failed",
                error_detail={"error": str(e)},
            )

    async def extract_metadata(self, token: str) -> TokenMetadata | None:
        """
        Extract metadata from a token without full validation.

        Useful for logging and debugging. Does not verify signature.

        Args:
            token: JWT token string

        Returns:
            TokenMetadata or None if token cannot be decoded
        """
        try:
            # Decode without verification (for metadata extraction only)
            unverified = jwt.decode(token, options={"verify_signature": False})

            # Get agent info from subject
            agent_id = UUID(unverified["sub"])

            return TokenMetadata(
                key_id=jwt.get_unverified_header(token).get("kid", "unknown"),
                algorithm=jwt.get_unverified_header(token).get("alg", "unknown"),
                agent_id=agent_id,
                agent_name=unverified.get("agent_name", "unknown"),
                agent_type=AgentType(unverified.get("agent_type", "autonomous")),
                trust_level=TrustLevel(unverified.get("trust_level", "delegated")),
                scopes=unverified.get("scopes", []),
            )

        except Exception as e:
            logger.warning("Failed to extract token metadata", error=str(e))
            return None

    async def introspect_token(
        self,
        token: str,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Introspect a token (RFC 7662 compatible).

        Args:
            token: JWT token string
            use_cache: Whether to use Redis cache for introspection results

        Returns:
            Introspection response dict
        """
        redis_client = get_redis_client()

        # Generate cache key from token hash (avoids collision from suffix matching)
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        cache_key = f"introspection:{token_hash}"

        # Try cache first if enabled
        if use_cache:
            cached_result = await redis_client.get_json(cache_key)
            if cached_result is not None:
                logger.debug("Token introspection cache hit", cache_key=cache_key)
                return cached_result

        # Check if token is in revocation blocklist
        # First, extract JTI from token without full validation
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            jti = unverified.get("jti")

            if jti:
                revoked = await redis_client.exists(f"revoked:{jti}")
                if revoked:
                    logger.info("Token is revoked", jti=jti)
                    inactive_response = {"active": False}
                    # Cache the inactive response briefly (no need to cache forever)
                    await redis_client.set_json(cache_key, inactive_response, ex=60)
                    return inactive_response
        except Exception as e:
            logger.debug("Failed to check revocation status", error=str(e))

        # Validate token
        validation_result = await self.validate_token(token)

        if not validation_result.valid or validation_result.claims is None:
            inactive_response = {"active": False}
            # Cache inactive responses briefly
            if use_cache:
                await redis_client.set_json(cache_key, inactive_response, ex=60)
            return inactive_response

        claims = validation_result.claims

        # Build RFC 7662 compliant response
        introspection_response: dict[str, Any] = {
            "active": True,
            "scope": " ".join(claims.scopes) if claims.scopes else None,
            "client_id": claims.sub,
            "username": claims.sub,  # Agent ID as username
            "token_type": claims.token_type,
            "exp": claims.exp,
            "iat": claims.iat,
            "sub": claims.sub,
            "aud": claims.aud,
            "iss": claims.iss,
            "jti": claims.jti,
            "agent_type": claims.agent_type.value,
            "trust_level": claims.trust_level.value,
            "parent_agent_id": str(claims.parent_agent_id) if claims.parent_agent_id else None,
        }

        # Cache the result with TTL = remaining token lifetime
        if use_cache:
            now = datetime.now(UTC)
            expires_at = datetime.fromtimestamp(claims.exp, UTC)
            ttl = int((expires_at - now).total_seconds())

            # Only cache if token has significant time left (> 5 seconds)
            if ttl > 5:
                await redis_client.set_json(cache_key, introspection_response, ex=ttl)
                # Also store JTI -> cache key mapping for cascading revocation
                await redis_client.set(f"jti_to_cache:{claims.jti}", cache_key, ex=ttl)
                logger.debug(
                    "Token introspection cached",
                    cache_key=cache_key,
                    ttl=ttl,
                    jti=claims.jti,
                )

        return introspection_response

    # Lua script for atomic cascading token revocation.
    # KEYS: [1] revoked:{jti}, [2] introspection_cache_key,
    #        [3] token_pair:{type}:{jti}
    # ARGV: [1] ttl, [2] max_ttl
    # Returns: {paired_jti, paired_cache_key, already_revoked} or nil values.
    _REVOKE_LUA = """
    -- Phase 1: revoke primary token and fetch paired info
    redis.call('SET', KEYS[1], '1', 'EX', tonumber(ARGV[1]))
    redis.call('DEL', KEYS[2])

    local paired_jti = redis.call('GET', KEYS[3])
    if not paired_jti then
        return {false, false, false}
    end

    -- Phase 2: cascading revocation of the paired token
    local revoked_key = 'revoked:' .. paired_jti
    local already_revoked = redis.call('EXISTS', revoked_key)
    if already_revoked == 0 then
        redis.call('SET', revoked_key, '1', 'EX', tonumber(ARGV[2]))
    end

    -- Invalidate paired token's introspection cache
    local jti_cache_key = 'jti_to_cache:' .. paired_jti
    local paired_cache_key = redis.call('GET', jti_cache_key)
    if paired_cache_key then
        redis.call('DEL', paired_cache_key)
        redis.call('DEL', jti_cache_key)
    end

    return {paired_jti, paired_cache_key or '', tostring(already_revoked)}
    """

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding its JTI to the blocklist.

        Implements cascading revocation: when an access token is revoked,
        its associated refresh token is also revoked, and vice versa.

        Uses a Lua script for atomic execution in a single Redis round trip.

        Args:
            token: JWT token string to revoke

        Returns:
            True if successfully revoked, False otherwise
        """
        redis_client = get_redis_client()

        try:
            # Extract JTI and expiration without full validation
            unverified = jwt.decode(token, options={"verify_signature": False})
            jti = unverified.get("jti")
            exp = unverified.get("exp")
            token_type = unverified.get("token_type", "access")

            if not jti or not exp:
                logger.warning("Token missing JTI or exp claim, cannot revoke")
                return False

            # Calculate TTL (how long until token would naturally expire)
            now = datetime.now(UTC)
            expires_at = datetime.fromtimestamp(exp, UTC)
            ttl = int((expires_at - now).total_seconds())

            # Only add to blocklist if token hasn't expired yet
            if ttl <= 0:
                logger.debug("Token already expired, no need to revoke", jti=jti)
                return True

            # Build keys for the Lua script
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            cache_key = f"introspection:{token_hash}"
            pair_key = f"token_pair:{token_type}:{jti}"

            max_ttl = max(
                settings.access_token_expire_minutes * 60,
                settings.refresh_token_expire_days * 24 * 60 * 60,
            )

            # Execute atomic Lua script: revoke + cache invalidate + cascade
            result = await redis_client.eval_script(
                self._REVOKE_LUA,
                keys=[f"revoked:{jti}", cache_key, pair_key],
                args=[str(ttl), str(max_ttl)],
            )

            logger.info("Token revoked", jti=jti, token_type=token_type, ttl=ttl)

            # Process Lua script results for logging and pair-mapping cleanup
            paired_jti = result[0] if result and result[0] else None
            if paired_jti:
                paired_cache_key = result[1] if result[1] else None
                already_revoked = result[2] == "1" if result[2] else False

                if token_type == "access":
                    logger.info(
                        "Cascading revocation: revoking paired refresh token",
                        access_jti=jti,
                        refresh_jti=paired_jti,
                    )
                else:
                    logger.info(
                        "Cascading revocation: revoking paired access token",
                        refresh_jti=jti,
                        access_jti=paired_jti,
                    )

                if not already_revoked:
                    logger.info("Paired token revoked", paired_jti=paired_jti)

                if paired_cache_key:
                    logger.debug(
                        "Invalidated cache for paired token",
                        paired_jti=paired_jti,
                        cache_key=paired_cache_key,
                    )

                # Clean up token pair mappings (two DELETE calls, use pipeline)
                await self._cleanup_pair_mappings(redis_client, token_type, jti, paired_jti)

            return True

        except Exception as e:
            logger.error("Failed to revoke token", error=str(e))
            return False

    @staticmethod
    async def _cleanup_pair_mappings(
        redis_client: Any,
        token_type: str,
        jti: str,
        paired_jti: str,
    ) -> None:
        """Delete token pair mapping keys using a pipeline."""
        try:
            async with redis_client.pipeline() as pipe:
                if token_type == "access":
                    pipe.delete(f"token_pair:access:{jti}")
                    pipe.delete(f"token_pair:refresh:{paired_jti}")
                else:
                    pipe.delete(f"token_pair:refresh:{jti}")
                    pipe.delete(f"token_pair:access:{paired_jti}")
                await pipe.execute()
        except Exception as e:
            logger.warning("Failed to clean up pair mappings", error=str(e))

    async def refresh_token_grant(self, refresh_token: str) -> TokenResponse:
        """
        Handle the refresh_token grant type.

        Validates the refresh token, detects replay attacks, revokes the old
        refresh token, and issues a new access + refresh token pair.

        Args:
            refresh_token: The refresh token presented by the client

        Returns:
            New TokenResponse with fresh access and refresh tokens

        Raises:
            TokenError: If token is invalid, expired, or a replay is detected
        """
        from sqlalchemy import select

        from agentauth.models.agent import Agent

        redis_client = get_redis_client()

        # Step 1: Decode without verification to extract JTI and claims
        try:
            unverified = jwt.decode(refresh_token, options={"verify_signature": False})
        except Exception as e:
            raise TokenError("Invalid refresh token format") from e

        refresh_jti = unverified.get("jti")
        token_type = unverified.get("token_type")
        agent_id_str = unverified.get("sub")
        access_token_jti = unverified.get("access_token_jti")
        scopes: list[str] = unverified.get("scopes", [])

        if token_type != "refresh":
            raise TokenError(
                "Token is not a refresh token",
                detail={"token_type": token_type},
            )

        if not refresh_jti or not agent_id_str:
            raise TokenError("Refresh token missing required claims")

        # Step 2: Replay attack detection — if token is already revoked, family is compromised
        is_revoked = await redis_client.exists(f"revoked:{refresh_jti}")
        if is_revoked:
            logger.warning(
                "Refresh token replay attack detected — revoking token family",
                refresh_jti=refresh_jti,
                agent_id=agent_id_str,
                access_token_jti=access_token_jti,
            )
            # Revoke the paired access token to protect the entire family
            if access_token_jti:
                already_revoked = await redis_client.exists(f"revoked:{access_token_jti}")
                if not already_revoked:
                    max_ttl = settings.access_token_expire_minutes * 60
                    await redis_client.set(f"revoked:{access_token_jti}", "1", ex=max_ttl)
                    logger.info(
                        "Revoked access token in compromised family", access_jti=access_token_jti
                    )

            raise TokenError(
                "Refresh token reuse detected — entire token family has been revoked",
                detail={"refresh_jti": refresh_jti},
            )

        # Step 3: Full signature and expiry validation
        validation_result = await self.validate_token(refresh_token, expected_token_type="refresh")
        if not validation_result.valid or validation_result.claims is None:
            raise TokenError(
                f"Refresh token validation failed: {validation_result.error}",
                detail={"error": validation_result.error},
            )

        claims = validation_result.claims

        # Step 4: Load and verify agent
        result = await self.session.execute(select(Agent).where(Agent.id == UUID(claims.sub)))
        agent = result.scalar_one_or_none()

        if agent is None:
            raise TokenError("Agent not found for refresh token", detail={"sub": claims.sub})

        if not agent.is_active():
            raise TokenError(
                "Agent is not active",
                detail={"agent_id": claims.sub, "status": agent.status.value},
            )

        # Step 5: Revoke old refresh token immediately (rotate-on-use)
        now = datetime.now(UTC)
        refresh_exp = datetime.fromtimestamp(claims.exp, UTC)
        refresh_ttl = max(0, int((refresh_exp - now).total_seconds()))
        await redis_client.set(f"revoked:{refresh_jti}", "1", ex=max(refresh_ttl, 1))
        logger.info("Old refresh token revoked on use", refresh_jti=refresh_jti)

        # Step 6: Issue new token pair with the same scopes
        new_token_response = await self.mint_token(
            agent=agent,
            scopes=scopes,
            token_type="access",
        )

        logger.info(
            "Refresh token grant completed",
            agent_id=str(agent.id),
            old_refresh_jti=refresh_jti,
            scopes=scopes,
        )

        return new_token_response

    @staticmethod
    def _generate_jti() -> str:
        """
        Generate a unique JWT ID.

        Returns:
            Random token ID string
        """
        return secrets.token_urlsafe(32)
