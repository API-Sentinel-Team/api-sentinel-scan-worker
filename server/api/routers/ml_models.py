"""ML model registry API."""
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.auth.rbac import RBAC
from server.modules.persistence.database import get_db
from server.modules.ml.model_registry import list_models, promote_model

router = APIRouter(tags=["ML Models"])


@router.get("/")
async def list_ml_models(
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    models = await list_models(db, account_id)
    return {"total": len(models), "models": [
        {
            "id": m.id,
            "name": m.name,
            "version": m.version,
            "status": m.status,
            "metrics": m.metrics,
            "created_at": m.created_at,
        } for m in models
    ]}


@router.post("/promote")
async def promote(
    model_id: str = Body(...),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    ok = await promote_model(db, account_id, model_id)
    if not ok:
        raise HTTPException(404, "Model not found")
    await db.commit()
    return {"status": "promoted", "id": model_id}
