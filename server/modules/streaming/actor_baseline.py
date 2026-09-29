from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import ActorBaseline


async def upsert_actor_baseline(
    db: AsyncSession,
    account_id: int,
    actor_id: str,
    endpoint_id: str,
    anomaly_score: float,
    metadata: Optional[Dict[str, float]] = None,
) -> None:
    stmt = (
        select(ActorBaseline)
        .where(
            ActorBaseline.account_id == account_id,
            ActorBaseline.actor_id == actor_id,
        )
    )
    result = await db.execute(stmt)
    baseline = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if baseline:
        history = baseline.endpoint_history or []
        if endpoint_id and endpoint_id not in history:
            history.append(endpoint_id)
            baseline.endpoint_history = history[-20:]
        baseline.anomaly_score = anomaly_score
        baseline.metadata_blob = metadata or {}
        baseline.last_seen = now
    else:
        baseline = ActorBaseline(
            account_id=account_id,
            actor_id=actor_id,
            endpoint_history=[endpoint_id] if endpoint_id else [],
            anomaly_score=anomaly_score,
            metadata_blob=metadata or {},
            last_seen=now,
        )
        db.add(baseline)
