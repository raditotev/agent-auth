"""Authentication endpoints."""

from typing import Annotated, Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Form, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import DbSession
from agentauth.core.exceptions import AuthenticationError, TokenError
from agentauth.models.agent import Agent
from agentauth.models.audit import ActorType, EventOutcome
from agentauth.schemas.token import (
    TokenIntrospectionResponse,
    TokenResponse,
)
from agentauth.services.audit import AuditService
from agentauth.services.credential import CredentialService
from agentauth.services.crypto import CryptoService
from agentauth.services.token import TokenService

logger = structlog.get_logger()

_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

router = APIRouter(prefix="/auth", tags=["Authentication"])


async def _parse_token_body(request: Request) -> dict[str, Any]:
    """
    Parse token endpoint request body from either JSON or form-encoded.

    Accepts:
    - application/json: {"grant_type": "client_credentials", ...}
    - application/x-www-form-urlencoded: grant_type=client_credentials&...
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return await request.json()
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_request", "error_description": "Invalid JSON body"},
            ) from e
    # Default: form-encoded (OAuth 2.0 standard)
    form = await request.form()
    return dict(form)


@router.get("/jwks")
async def get_jwks(
    session: DbSession,
) -> dict[str, list[dict]]:
    """
    Get JSON Web Key Set (JWKS) containing public keys for token verification.

    This endpoint returns all valid public keys that can be used to verify
    JWT signatures. It follows RFC 7517 (JSON Web Key) format.

    Keys are rotated automatically:
    - New keys generated every 30 days
    - Old keys remain valid for 60 additional days
    - Only active and non-revoked keys are published

    Returns:
        JWKS response with 'keys' array containing public keys
    """
    crypto_service = CryptoService(session)
    jwks = await crypto_service.export_jwks()

    logger.info("JWKS endpoint accessed", key_count=len(jwks.get("keys", [])))

    return jwks


@router.post(
    "/token",
    response_model=TokenResponse,
    description=(
        "OAuth 2.0 token endpoint. Accepts both `application/x-www-form-urlencoded` "
        "(standard OAuth) and `application/json` request bodies."
    ),
)
async def token_endpoint(
    request: Request,
    session: DbSession,
) -> TokenResponse:
    """
    OAuth 2.0 token endpoint supporting multiple grant types.

    Accepts **both** form-encoded and JSON request bodies:

    ```json
    {"grant_type": "client_credentials", "client_secret": "<key>", "scope": "api.read"}
    ```

    or form-encoded:

    ```
    grant_type=client_credentials&client_secret=<key>&scope=api.read
    ```

    Supported grant types:
    - client_credentials: Agent authenticates with API key
    - refresh_token: Exchange refresh token for new token pair
    - agent_delegation: Exchange parent delegation token for scoped access
    """
    body = await _parse_token_body(request)

    grant_type = body.get("grant_type")
    scope = body.get("scope")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    refresh_token = body.get("refresh_token")
    delegation_token = body.get("delegation_token")

    logger.info(
        "Token endpoint accessed",
        grant_type=grant_type,
        scope=scope,
        client_id=client_id,
    )

    subject_token = body.get("subject_token")
    subject_token_type = body.get("subject_token_type")
    requested_token_type = body.get("requested_token_type")
    audience = body.get("audience")

    if not grant_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "grant_type is required",
            },
        )

    if grant_type == "client_credentials":
        return await _handle_client_credentials(
            session=session,
            client_id=client_id,
            client_secret=client_secret,
            requested_scope=scope,
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(
            session=session,
            refresh_token=refresh_token,
        )
    elif grant_type == "agent_delegation":
        return await _handle_agent_delegation(
            session=session,
            delegation_token=delegation_token,
            client_secret=client_secret,
            requested_scope=scope,
        )
    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        return await _handle_token_exchange(
            session=session,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            requested_token_type=requested_token_type,
            requested_scope=scope,
            audience=audience,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unsupported_grant_type",
                "error_description": (
                    f"Grant type '{grant_type}' is not supported. "
                    "Supported: client_credentials, refresh_token, agent_delegation, "
                    "urn:ietf:params:oauth:grant-type:token-exchange"
                ),
            },
        )


async def _handle_client_credentials(
    session: AsyncSession,
    client_id: str | None,
    client_secret: str | None,
    requested_scope: str | None,
) -> TokenResponse:
    """
    Handle client_credentials grant type.

    Authenticates the agent using either:
    1. API key passed as client_secret (client_id is optional/ignored)
    2. client_id + client_secret pair

    Args:
        session: Database session
        client_id: Client identifier (optional for API key auth)
        client_secret: API key or client secret
        requested_scope: Space-separated requested scopes

    Returns:
        TokenResponse with access and refresh tokens

    Raises:
        HTTPException: 401 for authentication failures, 400 for invalid requests
    """
    if not client_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "client_secret is required",
            },
        )

    # Initialize services
    credential_service = CredentialService(session)
    token_service = TokenService(session)
    audit_service = AuditService(session)

    # Verify credential (API key or client secret)
    credential = await credential_service.verify_credential(client_secret)

    if credential is None:
        logger.warning(
            "Authentication failed - invalid credential",
            client_id=client_id,
        )
        # Record failed authentication attempt
        await audit_service.record_event(
            event_type="token.issued",
            action="authenticate",
            outcome=EventOutcome.FAILURE,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=None,
            metadata={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "error": "invalid_credential",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_client",
                "error_description": "Invalid client credentials",
            },
        )

    # Load the associated agent
    result = await session.execute(select(Agent).where(Agent.id == credential.agent_id))
    agent = result.scalar_one_or_none()

    if agent is None:
        logger.error(
            "Agent not found for credential",
            credential_id=str(credential.id),
            agent_id=str(credential.agent_id),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_client",
                "error_description": "Agent not found",
            },
        )

    # Check agent is active
    if not agent.is_active():
        logger.warning(
            "Authentication failed - agent not active",
            agent_id=str(agent.id),
            agent_status=agent.status.value,
        )
        await audit_service.record_event(
            event_type="token.issued",
            action="authenticate",
            outcome=EventOutcome.DENIED,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=agent.id,
            metadata={
                "grant_type": "client_credentials",
                "error": "agent_not_active",
                "agent_status": agent.status.value,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_client",
                "error_description": "Agent is not active",
            },
        )

    # Parse and validate requested scopes
    requested_scopes = _parse_scopes(requested_scope)

    # Validate scopes against credential's allowed scopes
    allowed_scopes = credential.scopes or []
    validated_scopes = _validate_scopes(requested_scopes, allowed_scopes)

    if validated_scopes is None:
        logger.warning(
            "Scope validation failed",
            agent_id=str(agent.id),
            requested_scopes=requested_scopes,
            allowed_scopes=allowed_scopes,
        )
        await audit_service.record_event(
            event_type="token.issued",
            action="authenticate",
            outcome=EventOutcome.DENIED,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=agent.id,
            metadata={
                "grant_type": "client_credentials",
                "error": "invalid_scope",
                "requested_scopes": requested_scopes,
                "allowed_scopes": allowed_scopes,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_scope",
                "error_description": "Requested scopes exceed credential's allowed scopes",
            },
        )

    # Mint tokens
    try:
        token_response = await token_service.mint_token(
            agent=agent,
            scopes=validated_scopes,
            token_type="access",
        )

        # Record successful token issuance
        await audit_service.record_event(
            event_type="token.issued",
            action="issued",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=agent.id,
            metadata={
                "grant_type": "client_credentials",
                "scopes": validated_scopes,
                "credential_id": str(credential.id),
            },
        )

        logger.info(
            "Token issued successfully",
            agent_id=str(agent.id),
            agent_name=agent.name,
            scopes=validated_scopes,
            grant_type="client_credentials",
        )

        await session.commit()

        return token_response

    except TokenError as e:
        logger.error(
            "Token minting failed",
            agent_id=str(agent.id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "server_error",
                "error_description": "Failed to issue token",
            },
        ) from e


async def _handle_refresh_token(
    session: AsyncSession,
    refresh_token: str | None,
) -> TokenResponse:
    """
    Handle the refresh_token grant type.

    Issues a new access + refresh token pair, rotates the refresh token,
    and detects replay attacks by revoking the entire token family on reuse.

    Args:
        session: Database session
        refresh_token: Refresh token from the client

    Returns:
        New TokenResponse with fresh tokens

    Raises:
        HTTPException: 400 if no refresh token provided, 401 on invalid/replayed token
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "refresh_token is required for refresh_token grant",
            },
        )

    token_service = TokenService(session)
    audit_service = AuditService(session)

    try:
        token_response = await token_service.refresh_token_grant(refresh_token)

        await audit_service.record_event(
            event_type="token.refreshed",
            action="refresh",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=None,
            metadata={"grant_type": "refresh_token"},
        )

        await session.commit()

        logger.info("Token refresh successful")
        return token_response

    except AuthenticationError as e:
        await audit_service.record_event(
            event_type="token.refreshed",
            action="refresh",
            outcome=EventOutcome.FAILURE,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=None,
            metadata={"grant_type": "refresh_token", "error": str(e)},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_grant", "error_description": str(e)},
        ) from e
    except TokenError as e:
        await audit_service.record_event(
            event_type="token.refreshed",
            action="refresh",
            outcome=EventOutcome.FAILURE,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=None,
            metadata={"grant_type": "refresh_token", "error": str(e)},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_grant", "error_description": str(e)},
        ) from e


async def _handle_agent_delegation(
    session: AsyncSession,
    delegation_token: str | None,
    client_secret: str | None,
    requested_scope: str | None,
) -> TokenResponse:
    """
    Handle the agent_delegation grant type.

    The requesting agent proves:
    1. Its own identity via API key (client_secret)
    2. A delegation token (access token from a parent agent with delegation_chain claim)

    The service validates the delegation chain, computes effective scopes
    (intersection across the chain), and issues an access token containing
    the delegation_chain claim.
    """
    from agentauth.services.delegation import DelegationService

    if not delegation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "delegation_token is required for agent_delegation grant",
            },
        )
    if not client_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "client_secret (API key) is required for agent_delegation grant",
            },
        )

    credential_service = CredentialService(session)
    token_service = TokenService(session)
    audit_service = AuditService(session)

    # Authenticate the requesting agent via API key
    credential = await credential_service.verify_credential(client_secret)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "Invalid API key"},
        )

    result = await session.execute(select(Agent).where(Agent.id == credential.agent_id))
    requesting_agent = result.scalar_one_or_none()
    if requesting_agent is None or not requesting_agent.is_active():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_client", "error_description": "Agent not found or inactive"},
        )

    # Validate the delegation token (it's a JWT from the parent agent)
    validation = await token_service.validate_token(delegation_token)
    if not validation.valid or validation.claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_grant",
                "error_description": f"Invalid delegation token: {validation.error}",
            },
        )

    parent_claims = validation.claims
    parent_scopes = parent_claims.scopes or []
    existing_chain = [str(uid) for uid in (parent_claims.delegation_chain or [])]
    if not existing_chain:
        existing_chain = [parent_claims.sub]  # at minimum the parent is in the chain

    # Check the requesting agent appears as the expected delegate
    # by resolving via delegation service
    delegation_service = DelegationService(session)
    effective_scopes, _ = await delegation_service.get_effective_scopes_and_depth(
        requesting_agent.id
    )

    # Scopes = intersection of parent scopes + agent's own effective scopes
    if effective_scopes is not None:
        scopes_to_grant = sorted(set(parent_scopes).intersection(effective_scopes))
    else:
        scopes_to_grant = parent_scopes

    # Apply requested scope filter
    if requested_scope:
        requested_list = _parse_scopes(requested_scope)
        scopes_to_grant = [s for s in scopes_to_grant if s in requested_list]

    # Build delegation chain claim
    full_chain = [UUID(uid) for uid in existing_chain] + [requesting_agent.id]

    try:
        token_response = await token_service.mint_token(
            agent=requesting_agent,
            scopes=scopes_to_grant,
            token_type="access",
            delegation_chain=full_chain,
        )

        await audit_service.record_event(
            event_type="token.issued",
            action="agent_delegation",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=requesting_agent.id,
            metadata={
                "grant_type": "agent_delegation",
                "parent_agent_id": parent_claims.sub,
                "scopes": scopes_to_grant,
                "delegation_chain": [str(uid) for uid in full_chain],
            },
        )

        await session.commit()

        logger.info(
            "Agent delegation grant issued",
            agent_id=str(requesting_agent.id),
            parent_agent_id=parent_claims.sub,
            scopes=scopes_to_grant,
            chain_length=len(full_chain),
        )
        return token_response

    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "error_description": str(e)},
        ) from e


async def _handle_token_exchange(
    session: AsyncSession,
    subject_token: str | None,
    subject_token_type: str | None,
    requested_token_type: str | None,
    requested_scope: str | None,
    audience: str | None,
) -> TokenResponse:
    """
    Handle the RFC 8693 token-exchange grant type.

    Validates a subject_token (an existing access token) and issues a new
    token for the same agent, optionally with reduced scope and/or a
    different audience. The delegation chain from the subject token is
    preserved in the new token.

    Common use cases:
    - Parent agent token → child agent token with reduced scope
    - Scope downgrade before passing credentials to a sub-agent
    - Re-targeting a token for a different audience

    Args:
        session: Database session
        subject_token: The token being exchanged (must be an access token)
        subject_token_type: Expected to be 'urn:ietf:params:oauth:token-type:access_token'
        requested_token_type: Token type to issue (only access_token supported)
        requested_scope: Space-separated scopes for the new token (must be subset of subject)
        audience: Optional audience override for the new token

    Returns:
        TokenResponse with new access token

    Raises:
        HTTPException: 400 for missing/invalid params, 401 for invalid subject token
    """
    if not subject_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": "subject_token is required for token-exchange grant",
            },
        )

    # We only support access token subjects
    if subject_token_type and subject_token_type != _ACCESS_TOKEN_TYPE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": (
                    f"Unsupported subject_token_type '{subject_token_type}'. "
                    f"Only '{_ACCESS_TOKEN_TYPE}' is supported."
                ),
            },
        )

    # We only issue access tokens
    if requested_token_type and requested_token_type != _ACCESS_TOKEN_TYPE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_request",
                "error_description": (
                    f"Unsupported requested_token_type '{requested_token_type}'. "
                    f"Only '{_ACCESS_TOKEN_TYPE}' is supported."
                ),
            },
        )

    token_service = TokenService(session)
    audit_service = AuditService(session)

    # Validate the subject token
    validation = await token_service.validate_token(subject_token, expected_token_type="access")
    if not validation.valid or validation.claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_grant",
                "error_description": f"Invalid subject_token: {validation.error}",
            },
        )

    claims = validation.claims

    # Load the agent from the subject token
    result = await session.execute(select(Agent).where(Agent.id == UUID(claims.sub)))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.is_active():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_grant",
                "error_description": "Agent not found or inactive",
            },
        )

    # Scope attenuation: new scopes must be a subset of subject token scopes
    subject_scopes = claims.scopes or []
    if requested_scope:
        requested_list = _parse_scopes(requested_scope)
        invalid = [s for s in requested_list if s not in subject_scopes]
        if invalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_scope",
                    "error_description": (
                        f"Requested scopes {invalid} are not present in subject_token"
                    ),
                },
            )
        granted_scopes = requested_list
    else:
        granted_scopes = subject_scopes

    # Preserve delegation chain from the subject token
    delegation_chain = claims.delegation_chain

    try:
        token_response = await token_service.mint_token(
            agent=agent,
            scopes=granted_scopes,
            audience=audience,
            token_type="access",
            delegation_chain=delegation_chain,
        )

        await audit_service.record_event(
            event_type="token.issued",
            action="token_exchange",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT,
            target_type="token",
            actor_id=agent.id,
            metadata={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_sub": claims.sub,
                "granted_scopes": granted_scopes,
                "audience": audience,
            },
        )

        await session.commit()

        logger.info(
            "Token exchange completed",
            agent_id=str(agent.id),
            granted_scopes=granted_scopes,
            audience=audience,
        )

        return token_response

    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "error_description": str(e)},
        ) from e


def _parse_scopes(scope_string: str | None) -> list[str]:
    """
    Parse space-separated scope string into list.

    Args:
        scope_string: Space-separated scope string or None

    Returns:
        List of scope strings
    """
    if not scope_string:
        return []

    return [s.strip() for s in scope_string.split() if s.strip()]


@router.post("/token/introspect", response_model=TokenIntrospectionResponse)
async def introspect_token(
    session: DbSession,
    token: Annotated[str, Form()],
    token_type_hint: Annotated[str | None, Form()] = None,
) -> TokenIntrospectionResponse:
    """
    Token introspection endpoint (RFC 7662).

    Validates and returns information about a token. This endpoint can be used
    by resource servers to validate access tokens presented by clients.

    The response follows RFC 7662 format:
    - If token is valid and active: returns detailed claims
    - If token is invalid/expired/revoked: returns {"active": false}

    Introspection results are cached in Redis with TTL matching the token's
    remaining lifetime for performance.

    Args:
        token: The token to introspect
        token_type_hint: Optional hint about token type (access_token/refresh_token)

    Returns:
        TokenIntrospectionResponse with active status and claims
    """
    logger.info(
        "Token introspection requested",
        token_type_hint=token_type_hint,
    )

    token_service = TokenService(session)
    audit_service = AuditService(session)

    # Introspect the token
    introspection_result = await token_service.introspect_token(token)

    # Record audit event
    await audit_service.record_event(
        event_type="token.introspected",
        action="introspect",
        outcome=EventOutcome.SUCCESS if introspection_result["active"] else EventOutcome.FAILURE,
        actor_type=ActorType.SYSTEM,
        target_type="token",
        actor_id=None,
        metadata={
            "active": introspection_result["active"],
            "token_type_hint": token_type_hint,
            "jti": introspection_result.get("jti"),
        },
    )

    await session.commit()

    logger.info(
        "Token introspection completed",
        active=introspection_result["active"],
        jti=introspection_result.get("jti"),
    )

    return TokenIntrospectionResponse(**introspection_result)


@router.post("/token/revoke")
async def revoke_token(
    session: DbSession,
    token: Annotated[str, Form()],
    token_type_hint: Annotated[str | None, Form()] = None,
) -> dict[str, str]:
    """
    Token revocation endpoint (RFC 7009).

    Revokes an access or refresh token, immediately invalidating it.
    Revoked tokens are added to a Redis blocklist and will fail introspection.

    The revocation is idempotent - revoking an already-revoked or invalid
    token succeeds without error.

    Args:
        token: The token to revoke
        token_type_hint: Optional hint about token type (access_token/refresh_token)

    Returns:
        Empty success response (RFC 7009 specifies 200 OK with no body)
    """
    logger.info(
        "Token revocation requested",
        token_type_hint=token_type_hint,
    )

    token_service = TokenService(session)
    audit_service = AuditService(session)

    # Revoke the token
    revoked = await token_service.revoke_token(token)

    # Record audit event
    await audit_service.record_event(
        event_type="token.revoked",
        action="revoke",
        outcome=EventOutcome.SUCCESS if revoked else EventOutcome.FAILURE,
        actor_type=ActorType.SYSTEM,
        target_type="token",
        actor_id=None,
        metadata={
            "revoked": revoked,
            "token_type_hint": token_type_hint,
        },
    )

    await session.commit()

    logger.info("Token revocation completed", revoked=revoked)

    # RFC 7009 specifies returning 200 OK regardless of whether token was valid
    return {}


def _scope_is_allowed(requested: str, allowed_patterns: list[str]) -> bool:
    """Check if a requested scope is covered by any of the allowed scope patterns.

    Supports wildcard patterns: 'files.*' covers 'files.read', 'files.write', etc.
    """
    for pattern in allowed_patterns:
        if pattern.endswith(".*"):
            prefix = pattern[:-1]  # strip '*', keep the dot
            if requested.startswith(prefix):
                return True
        elif pattern == requested:
            return True
    return False


def _validate_scopes(
    requested_scopes: list[str],
    allowed_scopes: list[str],
) -> list[str] | None:
    """
    Validate requested scopes against allowed scopes.

    Ensures no scope escalation: each requested scope must be covered
    by at least one allowed scope pattern (supports wildcards like 'files.*').
    If no scopes are requested, all allowed scopes are granted.

    Args:
        requested_scopes: Scopes requested by client
        allowed_scopes: Scopes allowed by credential (may include wildcards)

    Returns:
        Validated scopes to grant, or None if validation fails
    """
    # If no scopes requested, grant all allowed scopes
    if not requested_scopes:
        return allowed_scopes

    # Each requested scope must be covered by an allowed pattern
    for scope in requested_scopes:
        if not _scope_is_allowed(scope, allowed_scopes):
            return None

    return requested_scopes
