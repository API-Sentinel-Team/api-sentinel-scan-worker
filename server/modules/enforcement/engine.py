"""Enforcement engine for inline/out-of-band response actions."""
from __future__ import annotations

import uuid
import datetime
from typing import Dict, Any, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    WAFEvent,
    BlockedIP,
    EndpointBlock,
    RateLimitOverride,
    JWTRevokedToken,
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


async def push_waf_rule(
    db: AsyncSession,
    account_id: int,
    rule_id: str,
    source_ips: List[str] | None = None,
    path: str | None = None,
    severity: str = "HIGH",
) -> Dict[str, Any]:
    """Local WAF rule push stub — logs WAFEvent."""
    source_ips = source_ips or []
    if not source_ips and not path:
        return {"status": "SKIPPED", "reason": "no_target"}
    for ip in source_ips or [None]:
        db.add(WAFEvent(
            id=str(uuid.uuid4()),
            account_id=account_id,
            source_ip=ip,
            rule_id=rule_id,
            action="BLOCKED",
            path=path,
            severity=severity,
        ))
    return {"status": "SUCCESS", "rule_id": rule_id}


async def rate_limit_override(
    db: AsyncSession,
    account_id: int,
    endpoint_id: str,
    limit_rpm: int,
    duration_minutes: int,
    reason: str | None = None,
) -> Dict[str, Any]:
    expires_at = _now() + datetime.timedelta(minutes=duration_minutes)
    override = RateLimitOverride(
        id=str(uuid.uuid4()),
        account_id=account_id,
        endpoint_id=endpoint_id,
        limit_rpm=limit_rpm,
        duration_minutes=duration_minutes,
        reason=reason,
        expires_at=expires_at,
    )
    db.add(override)
    return {"status": "SUCCESS", "override_id": override.id, "expires_at": expires_at.isoformat()}


async def token_invalidate(
    db: AsyncSession,
    account_id: int,
    token_jti: str,
    expires_minutes: int = 1440,
    user_id: str | None = None,
) -> Dict[str, Any]:
    expires_at = _now() + datetime.timedelta(minutes=expires_minutes)
    # prevent duplicates
    result = await db.execute(
        select(JWTRevokedToken).where(JWTRevokedToken.token_jti == token_jti)
    )
    existing = result.scalar_one_or_none()
    if existing:
        return {"status": "SKIPPED", "reason": "already_revoked"}
    revoked = JWTRevokedToken(
        id=str(uuid.uuid4()),
        token_jti=token_jti,
        account_id=account_id,
        user_id=user_id,
        expires_at=expires_at,
    )
    db.add(revoked)
    return {"status": "SUCCESS", "revoked_id": revoked.id, "expires_at": expires_at.isoformat()}


async def circuit_breaker(
    db: AsyncSession,
    account_id: int,
    endpoint_id: str,
    duration_minutes: int = 60,
    reason: str | None = None,
    blocked_by: str = "AUTO",
) -> Dict[str, Any]:
    expires_at = _now() + datetime.timedelta(minutes=duration_minutes)
    block = EndpointBlock(
        id=str(uuid.uuid4()),
        account_id=account_id,
        endpoint_id=endpoint_id,
        reason=reason,
        blocked_by=blocked_by,
        expires_at=expires_at,
    )
    db.add(block)
    return {"status": "SUCCESS", "block_id": block.id, "expires_at": expires_at.isoformat()}
