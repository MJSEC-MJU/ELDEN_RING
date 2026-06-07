"""Webhook authentication dependency for ingestion endpoints.

Enforces a shared Bearer token on event-injection endpoints so that only
trusted producers (ModSecurity log shipper, Falco Sidekick, demo CLI) can
push events into the pipeline. Comparison is constant-time.

If WEBHOOK_AUTH_TOKEN is unset/empty, enforcement is disabled and a startup
warning is logged. Production deployments MUST set the token via K8s Secret.
"""

import logging
import secrets

from fastapi import Header, HTTPException, status

from src.config import settings

logger = logging.getLogger("runtime-defense.auth")

_BEARER_PREFIX = "Bearer "


def _auth_disabled() -> bool:
    return not settings.WEBHOOK_AUTH_TOKEN


if _auth_disabled():
    logger.warning(
        "WEBHOOK_AUTH_TOKEN is not set — webhook auth is DISABLED. "
        "All event-injection endpoints accept unauthenticated requests. "
        "Configure the runtime-defense-secrets K8s Secret in production."
    )


async def verify_webhook_token(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency: validates Authorization: Bearer <token>."""
    if _auth_disabled():
        return

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith(_BEARER_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer scheme required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presented = authorization[len(_BEARER_PREFIX):]
    if not secrets.compare_digest(presented, settings.WEBHOOK_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
        )
