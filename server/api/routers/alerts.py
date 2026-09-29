"""Alert management - create, acknowledge, resolve, dismiss security alerts."""

import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import Alert
from server.modules.auth.rbac import Permission, RBAC
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.persistence.database import get_db
from server.modules.response.playbook_executor import execute_playbooks
from server.modules.utils.redactor import Redactor

router = APIRouter()


class AlertCreate(BaseModel):
    title: str
    message: str | None = None
    severity: str = "MEDIUM"      # CRITICAL|HIGH|MEDIUM|LOW
    category: str | None = None   # SQL_INJECTION|XSS|BOLA|SCANNING etc
    source_ip: str | None = None
    endpoint: str | None = None


@router.get("/")
async def list_alerts(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(100, le=500),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    query = select(Alert).where(Alert.account_id == account_id)
    if status:
        query = query.where(Alert.status == status.upper())
    if severity:
        query = query.where(Alert.severity == severity.upper())
    query = query.order_by(Alert.created_at.desc()).limit(limit)
    result = await db.execute(query)
    rows = result.scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/summary")
async def alert_summary(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(Alert).where(Alert.account_id == account_id))
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "open": sum(1 for row in rows if row.status == "OPEN"),
        "acknowledged": sum(1 for row in rows if row.status == "ACKNOWLEDGED"),
        "resolved": sum(1 for row in rows if row.status == "RESOLVED"),
        "critical": sum(1 for row in rows if row.severity == "CRITICAL"),
        "high": sum(1 for row in rows if row.severity == "HIGH"),
        "medium": sum(1 for row in rows if row.severity == "MEDIUM"),
        "low": sum(1 for row in rows if row.severity == "LOW"),
    }


@router.post("/")
async def create_alert(
    body: AlertCreate,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    alert = Alert(
        id=str(uuid.uuid4()),
        account_id=account_id,
        title=Redactor.redact_text(body.title),
        message=Redactor.redact_text(body.message or "") if body.message is not None else None,
        severity=body.severity.upper(),
        category=body.category,
        source_ip=body.source_ip,
        endpoint=Redactor.redact_text(body.endpoint or "") if body.endpoint is not None else None,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    await dispatch_event(
        "alert.created",
        {
            "id": alert.id,
            "title": alert.title,
            "description": alert.message,
            "severity": alert.severity,
            "category": alert.category,
            "source_ip": alert.source_ip,
            "endpoint": alert.endpoint,
        },
        account_id,
        db,
    )
    await execute_playbooks(db, alert, evidence={"summary": Redactor.redact_text(alert.message or "")})
    await db.commit()
    return _serialize(alert)


@router.patch("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    by: str = Query("analyst"),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    alert = await _get_alert(alert_id, payload["account_id"], db)
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = Redactor.redact_text(by)
    await db.commit()
    return {"status": "acknowledged", "id": alert_id}


@router.patch("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    alert = await _get_alert(alert_id, payload["account_id"], db)
    alert.status = "RESOLVED"
    alert.resolved_at = datetime.datetime.now(datetime.timezone.utc)
    await db.commit()
    return {"status": "resolved", "id": alert_id}


@router.delete("/{alert_id}")
async def dismiss_alert(
    alert_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    alert = await _get_alert(alert_id, payload["account_id"], db)
    await db.delete(alert)
    await db.commit()
    return {"status": "dismissed", "id": alert_id}


async def _get_alert(alert_id: str, account_id: int, db: AsyncSession) -> Alert:
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.account_id == account_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _serialize(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "title": Redactor.redact_text(alert.title or ""),
        "message": Redactor.redact_text(alert.message or "") if alert.message is not None else None,
        "severity": alert.severity,
        "category": alert.category,
        "source_ip": alert.source_ip,
        "endpoint": Redactor.redact_text(alert.endpoint or "") if alert.endpoint is not None else None,
        "status": alert.status,
        "acknowledged_by": Redactor.redact_text(alert.acknowledged_by or "") if alert.acknowledged_by else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
