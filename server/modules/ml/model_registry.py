"""ML model registry and promotion logic."""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import MLModel


DEFAULT_MODELS = [
    ("bola_detector", "1.0.0"),
    ("ato_detector", "1.0.0"),
    ("scraping_detector", "1.0.0"),
]


async def ensure_default_models(db: AsyncSession, account_id: int) -> None:
    for name, version in DEFAULT_MODELS:
        result = await db.execute(
            select(MLModel).where(MLModel.account_id == account_id, MLModel.name == name)
        )
        if result.scalar_one_or_none():
            continue
        db.add(MLModel(
            id=str(uuid.uuid4()),
            account_id=account_id,
            name=name,
            version=version,
            status="SHADOW",
            metrics={"fp_rate": None, "tp_rate": None},
        ))


async def get_active_model(db: AsyncSession, account_id: int, name: str) -> Optional[MLModel]:
    result = await db.execute(
        select(MLModel)
        .where(MLModel.account_id == account_id, MLModel.name == name, MLModel.status == "ACTIVE")
        .limit(1)
    )
    return result.scalar_one_or_none()


async def list_models(db: AsyncSession, account_id: int) -> list[MLModel]:
    result = await db.execute(
        select(MLModel).where(MLModel.account_id == account_id).order_by(MLModel.created_at.desc())
    )
    return result.scalars().all()


async def promote_model(db: AsyncSession, account_id: int, model_id: str) -> bool:
    # set all models of same name to deprecated, then activate chosen
    result = await db.execute(select(MLModel).where(MLModel.id == model_id))
    model = result.scalar_one_or_none()
    if not model or model.account_id != account_id:
        return False

    await db.execute(
        update(MLModel)
        .where(MLModel.account_id == account_id, MLModel.name == model.name)
        .values(status="DEPRECATED")
    )
    await db.execute(
        update(MLModel)
        .where(MLModel.id == model_id)
        .values(status="ACTIVE")
    )
    return True
