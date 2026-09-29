"""OAuth2 SSO endpoints - GitHub OAuth flow plus provider management."""

import logging
import secrets
import uuid
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import OAuthProvider, User
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.auth.oauth_secrets import OAuthProviderSecretCodec
from server.modules.auth.oauth_github import GitHubOAuth
from server.modules.auth.rbac import require_admin
from server.modules.persistence.database import get_db

router = APIRouter(tags=["OAuth SSO"])
logger = logging.getLogger(__name__)

_STATE_TTL = 600
_oauth_states_fallback: dict = {}
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        from server.config import settings

        if settings.REDIS_URL:
            import redis.asyncio as aioredis

            _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            return _redis_client
    except Exception as exc:
        logger.warning("Redis unavailable for OAuth state store, using in-memory fallback: %s", exc)
    return None


async def _state_set(state: str, account_id: int) -> None:
    redis_client = _get_redis()
    if redis_client:
        try:
            await redis_client.setex(f"oauth_state:{state}", _STATE_TTL, str(account_id))
            return
        except Exception:
            pass
    _oauth_states_fallback[state] = account_id


async def _state_pop(state: str) -> Optional[int]:
    redis_client = _get_redis()
    if redis_client:
        try:
            value = await redis_client.getdel(f"oauth_state:{state}")
            if value is not None:
                return int(value)
        except Exception:
            pass
    return _oauth_states_fallback.pop(state, None)


def _make_github_oauth(provider: OAuthProvider) -> GitHubOAuth:
    try:
        from server.config import settings

        base = settings.OAUTH_REDIRECT_BASE_URL
    except Exception:
        base = "http://localhost:8000"
    return GitHubOAuth(
        client_id=provider.client_id or "",
        client_secret=OAuthProviderSecretCodec.client_secret(provider),
        redirect_uri=f"{base}/api/oauth/github/callback",
    )


@router.get("/providers")
async def list_providers(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(OAuthProvider).where(OAuthProvider.account_id == account_id))
    providers = result.scalars().all()
    return {
        "providers": [
            {
                "id": provider.id,
                "provider": provider.provider,
                "enabled": provider.enabled,
                "allowed_domains": provider.allowed_domains,
                "created_at": provider.created_at,
            }
            for provider in providers
        ]
    }


@router.post("/providers")
async def create_provider(
    provider: str = Body(..., description="github | google | okta | saml"),
    client_id: str = Body(...),
    client_secret: str = Body(...),
    allowed_domains: list = Body(default=[]),
    scopes: list = Body(default=[]),
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Register an OAuth provider with encrypted client secret storage."""
    account_id = payload["account_id"]
    provider_row = OAuthProvider(
        id=str(uuid.uuid4()),
        account_id=account_id,
        provider=provider,
        client_id=client_id,
        client_secret_enc=OAuthProviderSecretCodec.encrypt_secret(client_secret),
        allowed_domains=allowed_domains,
        scopes=scopes,
    )
    db.add(provider_row)
    await db.commit()
    return {"id": provider_row.id, "provider": provider, "status": "created"}


@router.delete("/providers/{provider_id}")
async def delete_provider(
    provider_id: str,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(OAuthProvider).where(
            OAuthProvider.id == provider_id,
            OAuthProvider.account_id == account_id,
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(404, "Provider not found")
    await db.delete(provider)
    await db.commit()
    return {"deleted": provider_id}


@router.get("/github/authorize")
async def github_authorize(
    account_id: int = Query(..., ge=1),
    db: AsyncSession = Depends(get_db),
):
    """Step 1: Return the GitHub authorization URL for a specific account."""
    result = await db.execute(
        select(OAuthProvider).where(
            OAuthProvider.account_id == account_id,
            OAuthProvider.provider == "github",
            OAuthProvider.enabled == True,
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(404, "GitHub OAuth provider not configured for this account")
    state = secrets.token_urlsafe(16)
    await _state_set(state, account_id)
    oauth = _make_github_oauth(provider)
    return {"authorization_url": oauth.get_authorization_url(state=state), "state": state}


@router.get("/github/callback")
async def github_callback(
    code: str = Query(...),
    state: str = Query(""),
    db: AsyncSession = Depends(get_db),
):
    """Step 2: Exchange code for token, upsert user, return JWT."""
    account_id = await _state_pop(state)
    if account_id is None:
        raise HTTPException(400, "OAuth state is missing or expired")

    result = await db.execute(
        select(OAuthProvider).where(
            OAuthProvider.account_id == account_id,
            OAuthProvider.provider == "github",
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(400, "GitHub OAuth not configured")

    oauth = _make_github_oauth(provider)
    access_token = await oauth.exchange_code_for_token(code)
    if not access_token:
        raise HTTPException(400, "Failed to exchange OAuth code for token")

    user_info = await oauth.get_user_info(access_token)
    if not user_info or not user_info.get("email"):
        raise HTTPException(400, "Could not retrieve user email from GitHub")

    email = user_info["email"]
    if provider.allowed_domains:
        domain = email.split("@")[-1]
        if domain not in provider.allowed_domains:
            raise HTTPException(403, f"Email domain '{domain}' is not allowed")

    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            account_id=account_id,
            email=email,
            password_hash="oauth_github",
            role="MEMBER",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    token = JWTIssuer.create_access_token(
        {
            "sub": user.id,
            "email": email,
            "role": user.role,
            "account_id": account_id,
        }
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "email": email,
        "provider": "github",
        "name": user_info.get("name"),
    }
