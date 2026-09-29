"""Tenant retention policy API."""
import uuid
from fastapi import APIRouter, Depends, Body, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.models.core import TenantRetentionPolicy
from server.modules.auth.audit import log_action
from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.modules.privacy.retention import invalidate_retention_policy, get_retention_policy
from server.modules.utils.redactor import Redactor

router = APIRouter(tags=["Retention"])


@router.get("/")
async def get_policy(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
):
    account_id = payload.get("account_id")
    return _serialize_policy(await get_retention_policy(db, account_id))


@router.put("/")
async def upsert_policy(
    full_payload_retention: bool = Body(default=False),
    retain_request_headers: bool = Body(default=False),
    retain_response_bodies: bool = Body(default=False),
    retention_encryption_key_id: str | None = Body(default=None),
    retention_period_days: int = Body(default=90),
    pii_categories_to_retain: list | None = Body(default=None),
    pii_vault_enabled: bool = Body(default=True),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
):
    account_id = payload.get("account_id")
    if retention_period_days < 1 or retention_period_days > 3650:
        raise HTTPException(status_code=400, detail="retention_period_days must be between 1 and 3650")

    result = await db.execute(
        select(TenantRetentionPolicy).where(TenantRetentionPolicy.account_id == account_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        policy = TenantRetentionPolicy(
            id=str(uuid.uuid4()),
            account_id=account_id,
        )
        db.add(policy)

    policy.full_payload_retention = full_payload_retention
    policy.retain_request_headers = retain_request_headers
    policy.retain_response_bodies = retain_response_bodies
    policy.retention_encryption_key_id = retention_encryption_key_id
    policy.retention_period_days = retention_period_days
    policy.pii_categories_to_retain = pii_categories_to_retain or []
    policy.pii_vault_enabled = pii_vault_enabled

    await log_action(
        db=db,
        account_id=account_id,
        action="RETENTION_POLICY_UPDATED",
        user_id=payload.get("user_id") or payload.get("sub"),
        resource_type="retention_policy",
        resource_id=str(account_id),
        details={
            "full_payload_retention": full_payload_retention,
            "retain_request_headers": retain_request_headers,
            "retain_response_bodies": retain_response_bodies,
            "retention_period_days": retention_period_days,
            "pii_vault_enabled": pii_vault_enabled,
        },
    )
    await db.commit()
    invalidate_retention_policy(account_id)
    return {"status": "updated", "account_id": account_id}


def _serialize_policy(policy: dict) -> dict:
    safe_policy = dict(policy)
    if safe_policy.get("retention_encryption_key_id"):
        safe_policy["retention_encryption_key_id"] = Redactor.redact_text(
            str(safe_policy["retention_encryption_key_id"])
        )
    safe_policy["pii_categories_to_retain"] = Redactor.redact_json(
        safe_policy.get("pii_categories_to_retain") or []
    )
    return safe_policy
