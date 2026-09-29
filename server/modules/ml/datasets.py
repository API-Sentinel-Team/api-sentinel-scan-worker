"""Feature vector dataset preparation for ML training."""
from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import FeatureVector
from server.config import settings


def _flatten_features(features: Dict) -> Tuple[List[str], List[float]]:
    keys = sorted([k for k, v in features.items() if isinstance(v, (int, float))])
    values = [float(features[k]) for k in keys]
    return keys, values


async def load_feature_dataset(
    db: AsyncSession,
    account_id: int,
    limit: int | None = None,
) -> Tuple[np.ndarray, List[str]]:
    """Load feature vectors for a tenant and return (X, feature_keys)."""
    limit = limit or settings.ML_TRAINING_MAX_SAMPLES
    result = await db.execute(
        select(FeatureVector)
        .where(FeatureVector.account_id == account_id)
        .order_by(FeatureVector.created_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    if not rows:
        return np.zeros((0, 0)), []

    feature_keys: List[str] = []
    matrix: List[List[float]] = []
    for row in rows:
        keys, values = _flatten_features(row.features or {})
        if not feature_keys:
            feature_keys = keys
        # align values to feature_keys
        row_vec = []
        for key in feature_keys:
            row_vec.append(float((row.features or {}).get(key, 0.0)))
        matrix.append(row_vec)

    return np.array(matrix, dtype=float), feature_keys
