"""External recon ingestion API."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import RBAC
from server.modules.persistence.database import get_db
from server.modules.recon.processor import ReconProcessor
from server.models.core import ExternalReconFinding

router = APIRouter(tags=["recon"])
_recon = ReconProcessor()


@router.post("/findings")
async def ingest_recon_findings(
    payload: dict = Depends(RBAC.require_auth),
    source: str = Body(..., embed=True),
    items: List[dict] = Body(default=[]),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    if not source:
        raise HTTPException(status_code=400, detail="source is required")
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail="items must be a non-empty list")
    stats = await _recon.ingest(db, account_id, source, items)
    await db.commit()
    return {"success": True, "stats": stats}


@router.get("/findings")
async def list_recon_findings(
    payload: dict = Depends(RBAC.require_auth),
    status: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    stmt = select(ExternalReconFinding).where(ExternalReconFinding.account_id == account_id)
    if status:
        stmt = stmt.where(ExternalReconFinding.status == status.upper())
    if source:
        stmt = stmt.where(ExternalReconFinding.source == source)
    stmt = stmt.order_by(ExternalReconFinding.last_seen_at.desc()).limit(limit)
    result = await db.execute(stmt)
    findings = result.scalars().all()
    return {
        "count": len(findings),
        "items": [
            {
                "id": f.id,
                "source": f.source,
                "method": f.method,
                "url": f.url,
                "host": f.host,
                "path": f.path,
                "path_pattern": f.path_pattern,
                "confidence": f.confidence,
                "status": f.status,
                "endpoint_id": f.endpoint_id,
                "first_seen_at": f.first_seen_at,
                "last_seen_at": f.last_seen_at,
            }
            for f in findings
        ],
    }


@router.post("/findings/{finding_id}/ignore")
async def ignore_recon_finding(
    finding_id: str,
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    finding = await db.scalar(
        select(ExternalReconFinding).where(
            ExternalReconFinding.account_id == account_id,
            ExternalReconFinding.id == finding_id,
        )
    )
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.status = "IGNORED"
    await db.commit()
    return {"success": True}


@router.post("/findings/{finding_id}/confirm")
async def confirm_recon_finding(
    finding_id: str,
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    finding = await db.scalar(
        select(ExternalReconFinding).where(
            ExternalReconFinding.account_id == account_id,
            ExternalReconFinding.id == finding_id,
        )
    )
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.status = "CONFIRMED"
    await db.commit()
    return {"success": True}
