"""Block list - manage blocked IPs, auto-block high-risk actors, export nginx deny list."""

import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import BlockedIP, ThreatActor
from server.modules.auth.rbac import RBAC, require_security_engineer
from server.modules.persistence.database import get_db

router = APIRouter()


class BlockRequest(BaseModel):
    ip: str
    reason: str | None = None
    expires_in_hours: float | None = None
    risk_score: float = 0.0


@router.get("/")
async def list_blocked(
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(BlockedIP)
        .where(BlockedIP.account_id == account_id)
        .order_by(BlockedIP.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = result.scalars().all()
    now = datetime.datetime.now(datetime.timezone.utc)
    return [
        {
            "id": row.id,
            "ip": row.ip,
            "reason": row.reason,
            "blocked_by": row.blocked_by,
            "risk_score": row.risk_score,
            "event_count": row.event_count,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "expired": row.expires_at is not None and row.expires_at < now,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@router.get("/summary")
async def block_summary(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(BlockedIP).where(BlockedIP.account_id == account_id))
    rows = result.scalars().all()
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "total": len(rows),
        "auto": sum(1 for row in rows if row.blocked_by == "AUTO"),
        "manual": sum(1 for row in rows if row.blocked_by == "MANUAL"),
        "sensor": sum(1 for row in rows if row.blocked_by == "SENSOR"),
        "expiring_soon": sum(
            1
            for row in rows
            if row.expires_at and (row.expires_at - now).total_seconds() < 86400
        ),
    }


@router.post("/")
async def block_ip(
    body: BlockRequest,
    payload: dict = Depends(require_security_engineer),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    existing = await db.execute(
        select(BlockedIP).where(BlockedIP.ip == body.ip, BlockedIP.account_id == account_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"{body.ip} is already blocked")

    expires_at = None
    if body.expires_in_hours:
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=body.expires_in_hours
        )

    entry = BlockedIP(
        id=str(uuid.uuid4()),
        account_id=account_id,
        ip=body.ip,
        reason=body.reason or "Manual block",
        blocked_by="MANUAL",
        risk_score=body.risk_score,
        expires_at=expires_at,
    )
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"{body.ip} is already blocked")
    return {"status": "blocked", "ip": body.ip}


@router.delete("/{ip}")
async def unblock_ip(
    ip: str,
    payload: dict = Depends(require_security_engineer),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(BlockedIP).where(BlockedIP.ip == ip, BlockedIP.account_id == account_id)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail=f"{ip} not found in block list")
    await db.delete(entry)
    await db.commit()
    return {"status": "unblocked", "ip": ip}


@router.get("/export/nginx", response_class=PlainTextResponse)
async def export_nginx_deny(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    """Export as nginx deny list - paste into nginx.conf or /etc/nginx/blocklist.conf."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(BlockedIP)
        .where(BlockedIP.account_id == account_id)
        .order_by(BlockedIP.created_at.desc())
    )
    rows = result.scalars().all()
    lines = [
        "# AppSentinel Block List - auto-generated",
        f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"# Total: {len(rows)} blocked IPs",
        "",
    ]
    for row in rows:
        comment = f"# {row.reason or 'blocked'} | risk={row.risk_score:.0f} | by={row.blocked_by}"
        lines.append(comment)
        lines.append(f"deny {row.ip};")
    lines.append("")
    lines.append("# End of block list")
    return "\n".join(lines)


@router.post("/auto")
async def auto_block_high_risk(
    threshold: float = Query(80.0, description="Risk score threshold"),
    payload: dict = Depends(require_security_engineer),
    db: AsyncSession = Depends(get_db),
):
    """Auto-block all ThreatActors with risk_score >= threshold not already blocked."""
    account_id = payload["account_id"]
    actors_result = await db.execute(
        select(ThreatActor).where(
            ThreatActor.account_id == account_id,
            ThreatActor.risk_score >= threshold,
        )
    )
    actors = actors_result.scalars().all()

    existing_result = await db.execute(
        select(BlockedIP.ip).where(BlockedIP.account_id == account_id)
    )
    already_blocked = {row for row in existing_result.scalars().all()}

    newly_blocked = []
    for actor in actors:
        if actor.source_ip in already_blocked:
            continue
        db.add(
            BlockedIP(
                id=str(uuid.uuid4()),
                account_id=account_id,
                ip=actor.source_ip,
                reason=f"Auto-block: risk_score={actor.risk_score:.0f}, events={actor.event_count}",
                blocked_by="AUTO",
                risk_score=actor.risk_score,
                event_count=actor.event_count,
            )
        )
        newly_blocked.append(actor.source_ip)

    await db.commit()
    return {
        "status": "done",
        "newly_blocked": len(newly_blocked),
        "ips": newly_blocked,
        "threshold": threshold,
    }
