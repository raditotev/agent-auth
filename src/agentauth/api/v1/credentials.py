"""API endpoints for credential management."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.core.exceptions import CredentialError, NotFoundError
from agentauth.schemas.credential import (
    CredentialCreate,
    CredentialCreateResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    CredentialResponse,
    CredentialRotateResponse,
)
from agentauth.services.credential import CredentialService

logger = structlog.get_logger()

router = APIRouter(prefix="/credentials", tags=["credentials"])


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
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CredentialCreateResponse:
    """
    Create a new credential.

    The raw API key is only returned once. Store it securely.
    """
    try:
        service = CredentialService(session)

        credential, raw_key = await service.create_credential(
            agent_id=credential_data.agent_id,
            credential_type=credential_data.type,
            scopes=credential_data.scopes,
            expires_at=credential_data.expires_at,
            metadata=credential_data.credential_metadata,
            # TODO: Extract actor_id from authenticated request context
            actor_id=None,
        )

        # Convert to response model
        credential_response = CredentialResponse(
            id=credential.id,
            agent_id=credential.agent_id,
            type=credential.type,
            prefix=credential.prefix,
            scopes=credential.scopes,
            expires_at=credential.expires_at,
            last_used_at=credential.last_used_at,
            last_rotated_at=credential.last_rotated_at,
            revoked_at=credential.revoked_at,
            credential_metadata=credential.credential_metadata,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
            is_valid=credential.is_valid(),
        )

        return CredentialCreateResponse(
            credential=credential_response,
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
    session: Annotated[AsyncSession, Depends(get_session)],
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

        # Convert to response models
        credential_responses = [
            CredentialResponse(
                id=cred.id,
                agent_id=cred.agent_id,
                type=cred.type,
                prefix=cred.prefix,
                scopes=cred.scopes,
                expires_at=cred.expires_at,
                last_used_at=cred.last_used_at,
                last_rotated_at=cred.last_rotated_at,
                revoked_at=cred.revoked_at,
                credential_metadata=cred.credential_metadata,
                created_at=cred.created_at,
                updated_at=cred.updated_at,
                is_valid=cred.is_valid(),
            )
            for cred in credentials
        ]

        return CredentialListResponse(
            data=credential_responses,
            meta={
                "total": len(credential_responses),
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
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CredentialDetailResponse:
    """
    Get credential details.

    API key is masked - only prefix is shown.
    """
    try:
        service = CredentialService(session)

        credential = await service.get_credential(credential_id)

        credential_response = CredentialResponse(
            id=credential.id,
            agent_id=credential.agent_id,
            type=credential.type,
            prefix=credential.prefix,
            scopes=credential.scopes,
            expires_at=credential.expires_at,
            last_used_at=credential.last_used_at,
            last_rotated_at=credential.last_rotated_at,
            revoked_at=credential.revoked_at,
            credential_metadata=credential.credential_metadata,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
            is_valid=credential.is_valid(),
        )

        return CredentialDetailResponse(
            data=credential_response,
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
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CredentialRotateResponse:
    """
    Rotate credential.

    Old key is immediately revoked. New key is returned ONCE.
    """
    try:
        service = CredentialService(session)

        old_cred, new_cred, raw_key = await service.rotate_credential(
            credential_id=credential_id,
            # TODO: Extract actor_id from authenticated request context
            actor_id=None,
        )

        old_response = CredentialResponse(
            id=old_cred.id,
            agent_id=old_cred.agent_id,
            type=old_cred.type,
            prefix=old_cred.prefix,
            scopes=old_cred.scopes,
            expires_at=old_cred.expires_at,
            last_used_at=old_cred.last_used_at,
            last_rotated_at=old_cred.last_rotated_at,
            revoked_at=old_cred.revoked_at,
            credential_metadata=old_cred.credential_metadata,
            created_at=old_cred.created_at,
            updated_at=old_cred.updated_at,
            is_valid=old_cred.is_valid(),
        )

        new_response = CredentialResponse(
            id=new_cred.id,
            agent_id=new_cred.agent_id,
            type=new_cred.type,
            prefix=new_cred.prefix,
            scopes=new_cred.scopes,
            expires_at=new_cred.expires_at,
            last_used_at=new_cred.last_used_at,
            last_rotated_at=new_cred.last_rotated_at,
            revoked_at=new_cred.revoked_at,
            credential_metadata=new_cred.credential_metadata,
            created_at=new_cred.created_at,
            updated_at=new_cred.updated_at,
            is_valid=new_cred.is_valid(),
        )

        return CredentialRotateResponse(
            old_credential=old_response,
            new_credential=new_response,
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
    session: Annotated[AsyncSession, Depends(get_session)],
) -> CredentialDetailResponse:
    """
    Revoke credential.

    This action is irreversible. The credential cannot be used after revocation.
    """
    try:
        service = CredentialService(session)

        credential = await service.revoke_credential(
            credential_id=credential_id,
            # TODO: Extract actor_id from authenticated request context
            actor_id=None,
        )

        credential_response = CredentialResponse(
            id=credential.id,
            agent_id=credential.agent_id,
            type=credential.type,
            prefix=credential.prefix,
            scopes=credential.scopes,
            expires_at=credential.expires_at,
            last_used_at=credential.last_used_at,
            last_rotated_at=credential.last_rotated_at,
            revoked_at=credential.revoked_at,
            credential_metadata=credential.credential_metadata,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
            is_valid=credential.is_valid(),
        )

        return CredentialDetailResponse(
            data=credential_response,
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
