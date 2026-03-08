"""API v1 package."""

from fastapi import APIRouter

from agentauth.api.v1 import admin, agents, audit, auth, credentials, delegations, policies, scopes, webhooks

api_router = APIRouter()

# Include all v1 routers
api_router.include_router(admin.router)
api_router.include_router(agents.router)
api_router.include_router(credentials.router)
api_router.include_router(auth.router)
api_router.include_router(scopes.router)
api_router.include_router(policies.router)
api_router.include_router(delegations.router)
api_router.include_router(audit.router)
api_router.include_router(webhooks.router)

__all__ = ["api_router"]
