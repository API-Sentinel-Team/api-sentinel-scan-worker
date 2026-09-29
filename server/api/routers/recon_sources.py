"""Recon source configuration API."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import Permission, RBAC
from server.modules.persistence.database import get_db
from server.modules.recon.scheduler import ReconSourceRunner
from server.modules.recon.secrets import ReconSourceSecretCodec
from server.models.core import ReconSourceConfig
from server.config import settings

router = APIRouter(tags=["recon"])
_runner = ReconSourceRunner()


@router.get("/sources")
async def list_recon_sources(
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(ReconSourceConfig).where(ReconSourceConfig.account_id == account_id)
    )
    sources = result.scalars().all()
    return {
        "count": len(sources),
        "items": [
            {
                "id": s.id,
                "name": s.name,
                "provider": s.provider,
                "enabled": s.enabled,
                "interval_seconds": s.interval_seconds,
                "config": ReconSourceSecretCodec.redacted_config(s),
                "last_run_at": s.last_run_at,
                "next_run_at": s.next_run_at,
                "last_status": s.last_status,
                "last_error": s.last_error,
            }
            for s in sources
        ],
    }


@router.post("/sources")
async def create_recon_source(
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE)),
    name: str = Body(...),
    provider: str = Body(...),
    enabled: bool = Body(default=True),
    interval_seconds: int = Body(default=settings.RECON_DEFAULT_INTERVAL_SECONDS),
    config: dict = Body(default_factory=dict),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    source = ReconSourceConfig(
        account_id=account_id,
        name=name,
        provider=provider,
        enabled=enabled,
        interval_seconds=interval_seconds,
        config=ReconSourceSecretCodec.encrypt_config(config),
    )
    db.add(source)
    await db.commit()
    return {"success": True, "id": source.id}


@router.patch("/sources/{source_id}")
async def update_recon_source(
    source_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE)),
    name: Optional[str] = Body(default=None),
    provider: Optional[str] = Body(default=None),
    enabled: Optional[bool] = Body(default=None),
    interval_seconds: Optional[int] = Body(default=None),
    config: Optional[dict] = Body(default=None),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    source = await db.scalar(
        select(ReconSourceConfig).where(
            ReconSourceConfig.account_id == account_id,
            ReconSourceConfig.id == source_id,
        )
    )
    if not source:
        raise HTTPException(status_code=404, detail="source not found")
    if name is not None:
        source.name = name
    if provider is not None:
        source.provider = provider
    if enabled is not None:
        source.enabled = enabled
    if interval_seconds is not None:
        source.interval_seconds = interval_seconds
    if config is not None:
        source.config = ReconSourceSecretCodec.encrypt_config(config)
    await db.commit()
    return {"success": True}


@router.delete("/sources/{source_id}")
async def delete_recon_source(
    source_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    source = await db.scalar(
        select(ReconSourceConfig).where(
            ReconSourceConfig.account_id == account_id,
            ReconSourceConfig.id == source_id,
        )
    )
    if not source:
        raise HTTPException(status_code=404, detail="source not found")
    await db.delete(source)
    await db.commit()
    return {"success": True}


@router.post("/sources/{source_id}/run")
async def run_recon_source(
    source_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.INTEGRATIONS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    source = await db.scalar(
        select(ReconSourceConfig).where(
            ReconSourceConfig.account_id == account_id,
            ReconSourceConfig.id == source_id,
        )
    )
    if not source:
        raise HTTPException(status_code=404, detail="source not found")
    result = await _runner.run_source(db, source)
    await db.commit()
    return result
