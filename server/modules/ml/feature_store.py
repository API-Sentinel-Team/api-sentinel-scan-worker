"""Feature store for ML models (simple per-hour aggregation)."""
from __future__ import annotations

import uuid
import datetime
from typing import Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import FeatureVector


def _hour_bucket(ts_ms: int) -> int:
    dt = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc)
    dt = dt.replace(minute=0, second=0, microsecond=0)
    return int(dt.timestamp())


async def update_feature_vector(
    db: AsyncSession,
    account_id: int,
    actor_id: str,
    endpoint_id: str,
    event: Dict[str, Any],
) -> FeatureVector:
    window_start = _hour_bucket(event.get("timestamp_ms", 0))
    result = await db.execute(
        select(FeatureVector).where(
            FeatureVector.account_id == account_id,
            FeatureVector.actor_id == actor_id,
            FeatureVector.endpoint_id == endpoint_id,
            FeatureVector.window_start == window_start,
        )
    )
    vec = result.scalar_one_or_none()
    if not vec:
        vec = FeatureVector(
            id=str(uuid.uuid4()),
            account_id=account_id,
            actor_id=actor_id,
            endpoint_id=endpoint_id,
            window_start=window_start,
            features={"count": 0, "errors": 0, "latency_sum": 0.0, "latency_n": 0},
        )
        db.add(vec)

    features = vec.features or {"count": 0, "errors": 0, "latency_sum": 0.0, "latency_n": 0}
    features["count"] = features.get("count", 0) + 1
    if event.get("response_code", 200) >= 400:
        features["errors"] = features.get("errors", 0) + 1
    if event.get("latency_ms"):
        features["latency_sum"] = features.get("latency_sum", 0.0) + float(event.get("latency_ms"))
        features["latency_n"] = features.get("latency_n", 0) + 1
    vec.features = features
    return vec
