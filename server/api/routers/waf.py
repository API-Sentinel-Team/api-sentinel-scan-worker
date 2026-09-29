"""WAF events router - log and query security events."""
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APIEndpoint, WAFEvent
from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.modules.utils.redactor import Redactor

router = APIRouter()

_ACTIONS = {"BLOCKED", "LOGGED", "ALLOWED"}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}


def _bounded(value: object, limit: int, *, default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    return Redactor.redact_text(text[:limit])


def _enum(value: object, allowed: set[str], field_name: str, *, default: str) -> str:
    text = str(value or default).strip().upper()
    if text not in allowed:
        raise HTTPException(status_code=400, detail=f"{field_name}: must be one of {sorted(allowed)}")
    return text


async def _validate_owned_endpoint(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_id: str | None,
) -> str | None:
    safe_endpoint_id = _bounded(endpoint_id, 100)
    if not safe_endpoint_id:
        return None
    endpoint = (
        await db.execute(
            select(APIEndpoint.id).where(
                APIEndpoint.id == safe_endpoint_id,
                APIEndpoint.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return safe_endpoint_id


def _serialize_event(event: WAFEvent) -> dict:
    return {
        "id": event.id,
        "source_ip": _bounded(event.source_ip, 45),
        "rule_id": _bounded(event.rule_id, 100),
        "action": event.action,
        "method": event.method,
        "path": _bounded(event.path, 2048),
        "severity": event.severity,
        "payload_snippet": _bounded(event.payload_snippet, 1000),
        "endpoint_id": event.endpoint_id,
        "created_at": str(event.created_at),
    }


@router.get("/")
async def get_waf_events(
    limit: int = Query(50, ge=1, le=500),
    action: str = Query(None, description="BLOCKED | LOGGED | ALLOWED"),
    severity: str = Query(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_READ)),
):
    """Returns security events blocked or logged by the WAF."""
    account_id = payload["account_id"]
    query = (
        select(WAFEvent)
        .where(WAFEvent.account_id == account_id)
        .order_by(desc(WAFEvent.created_at))
        .limit(limit)
    )
    if action:
        query = query.where(WAFEvent.action == _enum(action, _ACTIONS, "action", default="BLOCKED"))
    if severity:
        query = query.where(WAFEvent.severity == _enum(severity, _SEVERITIES, "severity", default="MEDIUM"))

    result = await db.execute(query)
    events = result.scalars().all()
    return {
        "total": len(events),
        "events": [_serialize_event(event) for event in events],
    }


@router.post("/events")
async def log_waf_event(
    source_ip: str = Body(...),
    rule_id: str = Body(...),
    action: str = Body("BLOCKED"),
    method: str = Body(None),
    path: str = Body(None),
    payload_snippet: str = Body(None),
    severity: str = Body("MEDIUM"),
    endpoint_id: str = Body(None),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_permission(Permission.TRAFFIC_MANAGE)),
):
    """Ingest a WAF security event."""
    account_id = payload["account_id"]
    validated_endpoint_id = await _validate_owned_endpoint(
        db,
        account_id=account_id,
        endpoint_id=endpoint_id,
    )
    event = WAFEvent(
        account_id=account_id,
        source_ip=_bounded(source_ip, 45),
        rule_id=_bounded(rule_id, 100),
        action=_enum(action, _ACTIONS, "action", default="BLOCKED"),
        method=_enum(method, _METHODS, "method", default="GET") if method else None,
        path=_bounded(path, 2048),
        payload_snippet=_bounded(payload_snippet, 1000),
        severity=_enum(severity, _SEVERITIES, "severity", default="MEDIUM"),
        endpoint_id=validated_endpoint_id,
    )
    db.add(event)
    await db.commit()
    return {"status": "logged", "id": event.id}


@router.post("/rules/reload")
async def reload_waf_rules(
    payload: dict = Depends(RBAC.require_permission(Permission.WORKFLOWS_MANAGE)),
):
    """Signal WAF to reload its ruleset (Coraza / ModSecurity hook point)."""
    return {"status": "rules_reloaded", "account_id": payload["account_id"]}
