import time
from typing import Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import TenantRetentionPolicy
from server.modules.utils.redactor import Redactor

_CACHE: dict[int, Dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 60


def _default_policy(account_id: int) -> Dict[str, Any]:
    return {
        "account_id": account_id,
        "full_payload_retention": False,
        "retain_request_headers": False,
        "retain_response_bodies": False,
        "retention_encryption_key_id": None,
        "retention_period_days": 90,
        "pii_categories_to_retain": [],
        "pii_vault_enabled": True,
    }


def invalidate_retention_policy(account_id: int) -> None:
    _CACHE.pop(account_id, None)


async def get_retention_policy(db: AsyncSession, account_id: int) -> Dict[str, Any]:
    now = time.time()
    cached = _CACHE.get(account_id)
    if cached and cached.get("expires_at", 0) > now:
        return cached["policy"]

    result = await db.execute(
        select(TenantRetentionPolicy).where(TenantRetentionPolicy.account_id == account_id)
    )
    row = result.scalar_one_or_none()
    policy = _default_policy(account_id)
    if row:
        policy.update({
            "full_payload_retention": row.full_payload_retention,
            "retain_request_headers": row.retain_request_headers,
            "retain_response_bodies": row.retain_response_bodies,
            "retention_encryption_key_id": row.retention_encryption_key_id,
            "retention_period_days": row.retention_period_days,
            "pii_categories_to_retain": row.pii_categories_to_retain or [],
            "pii_vault_enabled": row.pii_vault_enabled,
        })

    _CACHE[account_id] = {"expires_at": now + _CACHE_TTL_SECONDS, "policy": policy}
    return policy


def apply_retention_policy(policy: Dict[str, Any], req: Dict[str, Any], resp: Dict[str, Any]) -> Dict[str, Any]:
    """Apply retention policy to request/response payloads.

    Current behavior:
    - Headers are always redacted for secrets (Authorization, cookies, tokens).
    - Bodies are redacted unless full_payload_retention is enabled.
    """
    req_headers = req.get("headers") or {}
    resp_headers = resp.get("headers") or {}
    req_body = req.get("body")
    resp_body = resp.get("body")

    keep_headers = policy.get("full_payload_retention") or policy.get("retain_request_headers")
    redacted_headers = Redactor.redact_headers(req_headers) if keep_headers else {}
    redacted_resp_headers = Redactor.redact_headers(resp_headers) if keep_headers else {}

    if policy.get("full_payload_retention"):
        redacted_body = req_body
        redacted_resp_body = resp_body
    else:
        redacted_body = Redactor.redact_json(req_body) if req_body is not None else None
        if policy.get("retain_response_bodies"):
            redacted_resp_body = resp_body
        else:
            redacted_resp_body = Redactor.redact_json(resp_body) if resp_body is not None else None

    return {
        "request_headers": redacted_headers,
        "request_body": redacted_body,
        "response_headers": redacted_resp_headers,
        "response_body": redacted_resp_body,
    }
