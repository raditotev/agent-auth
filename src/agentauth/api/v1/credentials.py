"""API endpoints for credential management."""

from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import DbSession
from agentauth.core.exceptions import CredentialError, NotFoundError
from agentauth.models.audit import ActorType, EventOutcome
from agentauth.schemas.credential import (
    CredentialCreate,
    CredentialCreateResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    CredentialResponse,
    CredentialRotateResponse,
)
from agentauth.services.audit import AuditService
from agentauth.services.credential import CredentialService
from agentauth.services.identity import IdentityService

logger = structlog.get_logger()

router = APIRouter(prefix="/credentials", tags=["credentials"])


async def _check_credential_authority(
    caller_id: UUID,
    target_agent_id: UUID,
    session: AsyncSession,
) -> None:
    """
    Verify the caller has authority over the target agent for credential operations.

    Authority is granted only through the trust hierarchy (parent-child).
    Delegation relationships do NOT grant credential management authority.

    Raises:
        HTTPException 403 with RFC 7807 detail if authorisation fails.
    """
    identity_service = IdentityService(session)
    subtree_ids = await identity_service.get_subtree_agent_ids(caller_id)
    if target_agent_id not in subtree_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://agentauth.dev/problems/credential-authority-denied",
                "title": "Credential Authority Denied",
                "status": 403,
                "detail": (
                    "You do not have authority to manage credentials for this agent. "
                    "Only the agent itself, its parent, or an ancestor in the same "
                    "trust hierarchy may manage credentials."
                ),
                "instance": "/api/v1/credentials",
            },
            headers={"Content-Type": "application/problem+json"},
        )


@router.post(
    "",
    response_model=CredentialCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new credential",
    description=(
        "Generate a new API key for an agent. "
        "The raw key is returned ONCE in this response - save it securely."
    ),
)
async def create_credential(
    credential_data: CredentialCreate,
    session: DbSession,
    request: Request,
) -> CredentialCreateResponse:
    """
    Create a new credential.

    The raw API key is only returned once. Store it securely.
    """
    caller_id: UUID | None = getattr(request.state, "agent_id", None)

    if caller_id is not None:
        try:
            await _check_credential_authority(caller_id, credential_data.agent_id, session)
        except HTTPException:
            audit = AuditService(session)
            await audit.record_event(
                event_type="credential.creation_denied",
                action="create",
                outcome=EventOutcome.DENIED,
                actor_type=ActorType.AGENT,
                target_type="credential",
                actor_id=caller_id,
                target_id=credential_data.agent_id,
                metadata={
                    "target_agent_id": str(credential_data.agent_id),
                    "reason": "caller_outside_trust_hierarchy",
                },
            )
            await session.commit()
            raise

    try:
        service = CredentialService(session)

        credential, raw_key = await service.create_credential(
            agent_id=credential_data.agent_id,
            credential_type=credential_data.type,
            scopes=credential_data.scopes,
            expires_at=credential_data.expires_at,
            metadata=credential_data.credential_metadata,
            actor_id=caller_id,
        )

        return CredentialCreateResponse(
            credential=CredentialResponse.from_model(credential),
            raw_key=raw_key,
        )

    except Exception as e:
        logger.error(
            "credential_creation_failed",
            agent_id=str(credential_data.agent_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create credential",
        ) from e


@router.get(
    "",
    response_model=CredentialListResponse,
    summary="List credentials",
    description="List all credentials (masked). Optionally filter by agent.",
)
async def list_credentials(
    session: DbSession,
    agent_id: UUID | None = None,
    include_revoked: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> CredentialListResponse:
    """
    List credentials.

    API keys are masked - only prefix is shown.
    """
    try:
        service = CredentialService(session)

        credentials = await service.list_credentials(
            agent_id=agent_id,
            include_revoked=include_revoked,
            limit=limit,
            offset=offset,
        )

        return CredentialListResponse(
            data=[CredentialResponse.from_model(cred) for cred in credentials],
            meta={
                "total": len(credentials),
                "limit": limit,
                "offset": offset,
                "agent_id": str(agent_id) if agent_id else None,
            },
        )

    except Exception as e:
        logger.error("credential_list_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list credentials",
        ) from e


@router.get(
    "/{credential_id}",
    response_model=CredentialDetailResponse,
    summary="Get credential details",
    description="Get metadata for a specific credential (key is masked).",
)
async def get_credential(
    credential_id: UUID,
    session: DbSession,
) -> CredentialDetailResponse:
    """
    Get credential details.

    API key is masked - only prefix is shown.
    """
    try:
        service = CredentialService(session)

        credential = await service.get_credential(credential_id)

        return CredentialDetailResponse(
            data=CredentialResponse.from_model(credential),
            meta={"credential_id": str(credential_id)},
        )

    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(
            "credential_get_failed",
            credential_id=str(credential_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get credential",
        ) from e


@router.post(
    "/{credential_id}/rotate",
    response_model=CredentialRotateResponse,
    summary="Rotate credential",
    description=(
        "Rotate an API key - revokes old key and creates new one. "
        "New key is returned ONCE - save it securely."
    ),
)
async def rotate_credential(
    credential_id: UUID,
    session: DbSession,
    request: Request,
) -> CredentialRotateResponse:
    """
    Rotate credential.

    Old key is immediately revoked. New key is returned ONCE.
    """
    caller_id: UUID | None = getattr(request.state, "agent_id", None)
    service = CredentialService(session)

    # Fetch credential first for ownership check and 404 handling
    try:
        credential = await service.get_credential(credential_id)
    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e

    if caller_id is not None:
        await _check_credential_authority(caller_id, credential.agent_id, session)

    try:
        old_cred, new_cred, raw_key = await service.rotate_credential(
            credential_id=credential_id,
            actor_id=caller_id,
        )

        return CredentialRotateResponse(
            old_credential=CredentialResponse.from_model(old_cred),
            new_credential=CredentialResponse.from_model(new_cred),
            raw_key=raw_key,
        )

    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(
            "credential_rotation_failed",
            credential_id=str(credential_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate credential",
        ) from e


@router.delete(
    "/{credential_id}",
    response_model=CredentialDetailResponse,
    summary="Revoke credential",
    description="Revoke an API key. This action is irreversible.",
)
async def revoke_credential(
    credential_id: UUID,
    session: DbSession,
    request: Request,
) -> CredentialDetailResponse:
    """
    Revoke credential.

    This action is irreversible. The credential cannot be used after revocation.
    """
    caller_id: UUID | None = getattr(request.state, "agent_id", None)
    service = CredentialService(session)

    # Fetch credential first for ownership check and 404 handling
    try:
        credential = await service.get_credential(credential_id)
    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e

    if caller_id is not None:
        await _check_credential_authority(caller_id, credential.agent_id, session)

    try:
        credential = await service.revoke_credential(
            credential_id=credential_id,
            actor_id=caller_id,
        )

        return CredentialDetailResponse(
            data=CredentialResponse.from_model(credential),
            meta={
                "credential_id": str(credential_id),
                "message": "Credential revoked successfully",
            },
        )

    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except CredentialError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(
            "credential_revocation_failed",
            credential_id=str(credential_id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke credential",
        ) from e
