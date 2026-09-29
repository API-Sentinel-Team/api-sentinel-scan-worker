"""ML training and evaluation API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.modules.auth.rbac import RBAC
from server.modules.persistence.database import get_db
from server.modules.ml.training import train_isolation_forest
from server.models.core import MLModelEvaluation, MLModel

router = APIRouter(tags=["ML Training"])


@router.post("/train")
async def train_model(
    model_name: str = "isolation_forest",
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    result = await train_isolation_forest(db, account_id, model_name=model_name)
    await db.commit()
    return result


@router.get("/evaluations")
async def list_evaluations(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(MLModelEvaluation)
        .where(MLModelEvaluation.account_id == account_id)
        .order_by(MLModelEvaluation.created_at.desc())
        .limit(100)
    )
    rows = result.scalars().all()
    return {
        "count": len(rows),
        "evaluations": [
            {
                "model_id": r.model_id,
                "sample_count": r.sample_count,
                "metrics": r.metrics or {},
                "created_at": str(r.created_at),
            }
            for r in rows
        ],
    }


@router.get("/artifacts")
async def list_artifacts(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(MLModel)
        .where(MLModel.account_id == account_id)
        .order_by(MLModel.created_at.desc())
        .limit(100)
    )
    rows = result.scalars().all()
    return {
        "count": len(rows),
        "models": [
            {
                "id": r.id,
                "name": r.name,
                "version": r.version,
                "status": r.status,
                "artifact_path": r.artifact_path,
                "feature_keys": r.feature_keys or [],
                "metrics": r.metrics or {},
            }
            for r in rows
        ],
    }
