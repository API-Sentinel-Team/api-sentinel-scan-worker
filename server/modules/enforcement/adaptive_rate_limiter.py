"""Pure ASGI request-time enforcement middleware."""

from __future__ import annotations

import datetime
import logging
from typing import Optional

from sqlalchemy import and_, select
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from server.models.core import APIEndpoint, BlockedIP, EndpointBlock, RateLimitOverride
from server.modules.api_inventory.path_normalizer import PathNormalizer
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.cache import redis_cache
from server.modules.persistence.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

SKIP_ENFORCEMENT_PATH_PREFIXES = ("/api/health", "/api/auth", "/api/status")
BLOCKED_IP_CACHE_TTL = 30
ENDPOINT_BLOCK_CACHE_TTL = 30
RATE_LIMIT_CACHE_TTL = 60

_path_normalizer = PathNormalizer()


class AdaptiveRequestGuard:
    """Enforce BlockedIP, EndpointBlock, and RateLimitOverride at request time."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path
        if path.startswith(SKIP_ENFORCEMENT_PATH_PREFIXES):
            await self.app(scope, receive, send)
            return

        try:
            account_id = await self._extract_account_id(request)
        except Exception:
            logger.exception("adaptive_request_guard_auth_failed path=%s", path)
            await self.app(scope, receive, send)
            return

        if account_id is None:
            await self.app(scope, receive, send)
            return

        rate_limit_remaining = None
        try:
            source_ip = self._extract_source_ip(request)
            endpoint = await self._resolve_endpoint(
                account_id,
                request.method.upper(),
                path,
                request.url.hostname or "unknown",
            )

            if await self._check_blocked_ip(account_id, source_ip):
                response = JSONResponse({"error": "access_denied", "reason": "ip_blocked"}, status_code=403)
                await response(scope, receive, send)
                return

            if endpoint and await self._check_endpoint_block(account_id, endpoint.id):
                response = JSONResponse({"error": "service_unavailable", "reason": "endpoint_blocked"}, status_code=503)
                await response(scope, receive, send)
                return

            if endpoint:
                rate_limit_remaining = await self._enforce_rate_limit(account_id, endpoint.id, source_ip)
                if rate_limit_remaining is not None and rate_limit_remaining <= 0:
                    response = JSONResponse({"error": "too_many_requests", "reason": "rate_limit_exceeded"}, status_code=429)
                    await response(scope, receive, send)
                    return
        except Exception:
            logger.exception("adaptive_request_guard_failed path=%s", path)
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start" and rate_limit_remaining is not None:
                headers = MutableHeaders(scope=message)
                headers["X-RateLimit-Remaining"] = str(max(0, rate_limit_remaining))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _extract_source_ip(self, request: Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _extract_account_id(self, request: Request) -> Optional[int]:
        account_id_header = request.headers.get("X-Account-ID")
        if account_id_header:
            try:
                return int(account_id_header)
            except ValueError:
                pass

        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif request.cookies.get("access_token"):
            token = request.cookies.get("access_token")

        if not token:
            return None

        try:
            payload = await JWTIssuer.verify_token(token)
        except Exception:
            return None

        account_id = payload.get("account_id")
        try:
            return int(account_id) if account_id is not None else None
        except (TypeError, ValueError):
            return None

    async def _resolve_endpoint(
        self,
        account_id: int,
        method: str,
        request_path: str,
        host: str,
    ) -> APIEndpoint | None:
        path_pattern = _path_normalizer.normalize(request_path.split("?", 1)[0])
        host_key = (host or "unknown").lower()
        cache_key = f"endpoint_lookup:{account_id}:{method}:{host_key}:{path_pattern}"
        cached = await redis_cache.get_json(cache_key)
        if cached and cached.get("id"):
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(APIEndpoint).where(APIEndpoint.id == cached["id"]))
                endpoint = result.scalars().first()
                if endpoint is not None:
                    return endpoint

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(APIEndpoint)
                .where(
                    APIEndpoint.account_id == account_id,
                    APIEndpoint.method == method,
                    APIEndpoint.path_pattern == path_pattern,
                    APIEndpoint.host == host_key,
                )
                .limit(1)
            )
            endpoint = result.scalars().first()
            if endpoint is None:
                # Inventory is unique on (method, host, path). The same console
                # path exists once per captured host; never require exactly one row.
                result = await db.execute(
                    select(APIEndpoint)
                    .where(
                        APIEndpoint.account_id == account_id,
                        APIEndpoint.method == method,
                        APIEndpoint.path_pattern == path_pattern,
                    )
                    .limit(1)
                )
                endpoint = result.scalars().first()

        if endpoint is not None:
            await redis_cache.set_json(cache_key, {"id": endpoint.id}, ttl_seconds=RATE_LIMIT_CACHE_TTL)
        return endpoint

    async def _check_blocked_ip(self, account_id: int, source_ip: str) -> bool:
        cache_key = f"blocked:{account_id}:{source_ip}"
        cached = await redis_cache.get_json(cache_key)
        if cached is not None:
            return bool(cached.get("blocked", False))

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(BlockedIP).where(
                    and_(
                        BlockedIP.account_id == account_id,
                        BlockedIP.ip == source_ip,
                        (BlockedIP.expires_at.is_(None))
                        | (BlockedIP.expires_at > datetime.datetime.now(datetime.timezone.utc)),
                    )
                )
            )
            blocked_ip = result.scalar_one_or_none()

        is_blocked = blocked_ip is not None
        await redis_cache.set_json(cache_key, {"blocked": is_blocked}, ttl_seconds=BLOCKED_IP_CACHE_TTL)
        return is_blocked

    async def _check_endpoint_block(self, account_id: int, endpoint_id: str) -> bool:
        cache_key = f"endpoint_block:{account_id}:{endpoint_id}"
        cached = await redis_cache.get_json(cache_key)
        if cached is not None:
            return bool(cached.get("blocked", False))

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(EndpointBlock).where(
                    and_(
                        EndpointBlock.account_id == account_id,
                        EndpointBlock.endpoint_id == endpoint_id,
                        (EndpointBlock.expires_at.is_(None))
                        | (EndpointBlock.expires_at > datetime.datetime.now(datetime.timezone.utc)),
                    )
                )
            )
            blocked_endpoint = result.scalar_one_or_none()

        is_blocked = blocked_endpoint is not None
        await redis_cache.set_json(cache_key, {"blocked": is_blocked}, ttl_seconds=ENDPOINT_BLOCK_CACHE_TTL)
        return is_blocked

    async def _enforce_rate_limit(self, account_id: int, endpoint_id: str, source_ip: str) -> Optional[int]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(RateLimitOverride).where(
                    and_(
                        RateLimitOverride.account_id == account_id,
                        RateLimitOverride.endpoint_id == endpoint_id,
                        (RateLimitOverride.expires_at.is_(None))
                        | (RateLimitOverride.expires_at > datetime.datetime.now(datetime.timezone.utc)),
                    )
                )
            )
            override = result.scalar_one_or_none()

        if override is None:
            return None

        current_minute = int(datetime.datetime.now(datetime.timezone.utc).timestamp() / 60)
        counter_key = f"rate:{account_id}:{endpoint_id}:{source_ip}:{current_minute}"
        current_count = await redis_cache.incr(counter_key, ttl_seconds=RATE_LIMIT_CACHE_TTL)
        remaining = override.limit_rpm - current_count
        return remaining
