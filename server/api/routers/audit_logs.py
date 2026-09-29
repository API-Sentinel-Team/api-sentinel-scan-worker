"""Audit Logs - immutable trail of all user/system actions for compliance."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.future import select
from sqlalchemy import desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.models.core import AuditLog

router = APIRouter()

_FILTER_PATTERN = r"^[A-Za-z0-9_.:@-]+$"
_SAFETY_POLICY_KEYS = (
    "auth_profile_scope_policy",
    "state_change_policy",
    "target_guard_policy",
)


def _validate_filter(value: str | None, field_name: str, max_length: int) -> str | None:
    if value is None:
        return None
    try:
        return InputValidator.validate_string(
            value,
            field_name,
            max_length=max_length,
            allow_empty=False,
            pattern=_FILTER_PATTERN,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _safe_details(log: AuditLog):
    if log.details is not None:
        return _redacted_audit_details(log.details)
    if log.details_encrypted:
        return {"encrypted": True}
    return None


def _redacted_audit_details(details: dict):
    redacted = Redactor.redact_json(details)
    if isinstance(redacted, dict):
        scan_redacted = Redactor.redact_scan_result(details)
        _restore_safety_policy_metadata(redacted, scan_redacted)
    return redacted


def _restore_safety_policy_metadata(redacted: object, scan_redacted: object) -> None:
    if isinstance(redacted, dict) and isinstance(scan_redacted, dict):
        for key in _SAFETY_POLICY_KEYS:
            policy = scan_redacted.get(key)
            if isinstance(policy, dict):
                redacted[key] = policy
        for key, value in list(redacted.items()):
            _restore_safety_policy_metadata(value, scan_redacted.get(key))
        return
    if isinstance(redacted, list) and isinstance(scan_redacted, list):
        for redacted_item, scan_item in zip(redacted, scan_redacted):
            _restore_safety_policy_metadata(redacted_item, scan_item)


@router.get("/")
async def list_audit_logs(
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
    action: str = Query(None, description="Filter by action type"),
    resource_type: str = Query(None, description="Filter by resource type"),
    resource_id: str = Query(None, description="Filter by resource id (e.g. scan run_id)"),
    user_id: str = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    action = _validate_filter(action, "action", 100)
    resource_type = _validate_filter(resource_type, "resource_type", 50)
    resource_id = _validate_filter(resource_id, "resource_id", 100)
    user_id = _validate_filter(user_id, "user_id", 100)
    stmt = (
        select(AuditLog)
        .where(AuditLog.account_id == account_id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )
    if action:
        stmt = stmt.where(AuditLog.action == action.upper())
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type.lower())
    if resource_id:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)

    result = await db.execute(stmt)
    logs = result.scalars().all()
    return {
        "total": len(logs),
        "logs": [
            {
                "id": l.id,
                "action": l.action,
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "user_id": l.user_id,
                "details": _safe_details(l),
                "details_encrypted": bool(l.details_encrypted),
                "ip_address": l.ip_address,
                "ip_address_encrypted": bool(l.ip_address_encrypted),
                "created_at": str(l.created_at),
            }
            for l in logs
        ],
    }


@router.get("/actions")
async def list_action_types(
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Return distinct action types seen in audit logs."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(AuditLog.action, func.count(AuditLog.id))
        .where(AuditLog.account_id == account_id)
        .group_by(AuditLog.action)
        .order_by(desc(func.count(AuditLog.id)))
    )
    return {"actions": [{"action": row[0], "count": row[1]} for row in result.all()]}


@router.get("/stats")
async def audit_stats(
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    total = await db.scalar(
        select(func.count(AuditLog.id)).where(AuditLog.account_id == account_id)
    ) or 0
    by_resource = await db.execute(
        select(AuditLog.resource_type, func.count(AuditLog.id))
        .where(AuditLog.account_id == account_id)
        .group_by(AuditLog.resource_type)
    )
    return {
        "total_events": total,
        "by_resource": [{"resource_type": r[0], "count": r[1]} for r in by_resource.all()],
    }


async def log_action(
    db: AsyncSession,
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    user_id: str = None,
    account_id: int | None = None,
    details: dict = None,
    ip_address: str = None,
) -> None:
    """Helper called by other routers to write audit entries."""
    if account_id is None:
        raise ValueError("account_id is required")
    entry = AuditLog(
        account_id=account_id,
        user_id=user_id,
        action=action.upper(),
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        details=Redactor.redact_json(details or {}),
        ip_address=ip_address,
    )
    db.add(entry)
    # Caller must commit
