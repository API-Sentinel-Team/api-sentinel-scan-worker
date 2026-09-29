"""Enforcement APIs for inline/out-of-band response actions."""
import ipaddress
from fastapi import APIRouter, Depends, Body, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.models.core import EndpointBlock, RateLimitOverride, ResponseActionLog
from server.modules.enforcement.engine import (
    push_waf_rule,
    rate_limit_override,
    token_invalidate,
    circuit_breaker,
)
from server.modules.response.incident_orchestrator import handle_incident
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError

router = APIRouter(tags=["Enforcement"])


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _validate_uuid(value: str, field_name: str) -> str:
    try:
        return InputValidator.validate_uuid(value, field_name)
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_reason(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return InputValidator.validate_string(value, "reason", max_length=500, allow_empty=False)
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_integer(value, field_name: str, *, min_value: int, max_value: int) -> int:
    try:
        return InputValidator.validate_integer(
            value,
            field_name,
            min_value=min_value,
            max_value=max_value,
        )
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_severity(value: str) -> str:
    try:
        severity = InputValidator.validate_string(value, "severity", max_length=20, allow_empty=False).upper()
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise HTTPException(status_code=400, detail="severity: Must be one of LOW, MEDIUM, HIGH, CRITICAL")
    return severity


def _validate_ip(value: str, field_name: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{field_name}: Invalid IP address") from exc


def _validate_source_ips(source_ips: list) -> list[str]:
    try:
        InputValidator.validate_collection_size(source_ips, "source_ips", max_size=500)
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    validated: list[str] = []
    for index, raw_ip in enumerate(source_ips):
        validated.append(_validate_ip(raw_ip, f"source_ips[{index}]"))
    return validated


@router.post("/waf-rule")
async def waf_rule_push(
    rule_id: str = Body(default="auto-block"),
    source_ips: list = Body(default=[]),
    path: str | None = Body(default=None),
    severity: str = Body(default="HIGH"),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    try:
        validated_rule_id = InputValidator.validate_string(rule_id, "rule_id", max_length=100, allow_empty=False)
        validated_path = InputValidator.validate_path(path, "path") if path else None
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    result = await push_waf_rule(
        db,
        account_id,
        validated_rule_id,
        _validate_source_ips(source_ips),
        validated_path,
        _validate_severity(severity),
    )
    await db.commit()
    return result


@router.post("/rate-limit")
async def apply_rate_limit(
    endpoint_id: str = Body(...),
    limit_rpm: int = Body(default=60),
    duration_minutes: int = Body(default=60),
    reason: str | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    result = await rate_limit_override(
        db,
        account_id,
        _validate_uuid(endpoint_id, "endpoint_id"),
        _validate_integer(limit_rpm, "limit_rpm", min_value=1, max_value=100000),
        _validate_integer(duration_minutes, "duration_minutes", min_value=1, max_value=10080),
        _validate_reason(reason),
    )
    await db.commit()
    return result


@router.get("/rate-limit")
async def list_rate_limits(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(RateLimitOverride).where(RateLimitOverride.account_id == account_id)
        .order_by(RateLimitOverride.created_at.desc())
    )
    rows = result.scalars().all()
    return {"total": len(rows), "overrides": [
        {
            "id": r.id,
            "endpoint_id": r.endpoint_id,
            "limit_rpm": r.limit_rpm,
            "duration_minutes": r.duration_minutes,
            "reason": r.reason,
            "expires_at": r.expires_at,
            "created_at": r.created_at,
        } for r in rows
    ]}


@router.delete("/rate-limit/{override_id}")
async def delete_rate_limit(
    override_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    validated_override_id = _validate_uuid(override_id, "override_id")
    result = await db.execute(
        delete(RateLimitOverride).where(
            RateLimitOverride.id == validated_override_id,
            RateLimitOverride.account_id == account_id,
        )
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Override not found")
    await db.commit()
    return {"deleted": validated_override_id}


@router.post("/token-invalidate")
async def invalidate_token(
    token_jti: str = Body(...),
    expires_minutes: int = Body(default=1440),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    try:
        validated_token_jti = InputValidator.validate_string(
            token_jti,
            "token_jti",
            max_length=255,
            allow_empty=False,
            pattern=r"^[A-Za-z0-9_.:-]+$",
        )
    except ValidationError as exc:
        raise _bad_request(exc) from exc
    result = await token_invalidate(
        db,
        account_id,
        token_jti=validated_token_jti,
        expires_minutes=_validate_integer(
            expires_minutes,
            "expires_minutes",
            min_value=1,
            max_value=10080,
        ),
    )
    await db.commit()
    return result


@router.post("/endpoint-block")
async def block_endpoint(
    endpoint_id: str = Body(...),
    duration_minutes: int = Body(default=60),
    reason: str | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    result = await circuit_breaker(
        db,
        account_id,
        _validate_uuid(endpoint_id, "endpoint_id"),
        _validate_integer(duration_minutes, "duration_minutes", min_value=1, max_value=10080),
        _validate_reason(reason),
        blocked_by="MANUAL",
    )
    await db.commit()
    return result


@router.get("/endpoint-block")
async def list_endpoint_blocks(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(EndpointBlock).where(EndpointBlock.account_id == account_id)
        .order_by(EndpointBlock.created_at.desc())
    )
    rows = result.scalars().all()
    return {"total": len(rows), "blocks": [
        {
            "id": r.id,
            "endpoint_id": r.endpoint_id,
            "reason": r.reason,
            "blocked_by": r.blocked_by,
            "expires_at": r.expires_at,
            "created_at": r.created_at,
        } for r in rows
    ]}


@router.delete("/endpoint-block/{block_id}")
async def delete_endpoint_block(
    block_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    account_id = payload.get("account_id")
    validated_block_id = _validate_uuid(block_id, "block_id")
    result = await db.execute(
        delete(EndpointBlock).where(
            EndpointBlock.id == validated_block_id,
            EndpointBlock.account_id == account_id,
        )
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Block not found")
    await db.commit()
    return {"deleted": validated_block_id}


@router.get("/audit")
async def list_enforcement_audit(
    limit: int = Query(default=100, le=500),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_READ)),
):
    """List enforcement audit trail (last N ResponseActionLog entries)."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(ResponseActionLog)
        .where(ResponseActionLog.account_id == account_id)
        .order_by(ResponseActionLog.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "actions": [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "action_type": r.action_type,
                "status": r.status,
                "details": Redactor.redact_json(r.details or {}),
                "created_at": r.created_at,
            }
            for r in rows
        ],
    }


@router.post("/auto-remediate")
async def auto_remediate_threat(
    source_ip: str = Body(...),
    endpoint_id: str | None = Body(default=None),
    reason: str | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    """Trigger automatic remediation for a known threat actor."""
    account_id = payload.get("account_id")

    # Route through incident orchestrator
    result = await handle_incident(
        db,
        account_id,
        "manual.auto_remediate",
        "HIGH",
        _validate_ip(source_ip, "source_ip"),
        _validate_uuid(endpoint_id, "endpoint_id") if endpoint_id else None,
        {"reason": _validate_reason(reason) or "Manual remediation triggered"},
    )

    return {
        "alert_id": result["alert_id"],
        "actor_id": result["actor_id"],
        "risk_score": result["actor_risk_score"],
        "auto_blocked": result["auto_blocked"],
    }
