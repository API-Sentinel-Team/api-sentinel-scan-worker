"""ML training pipeline for anomaly detection."""
from __future__ import annotations

import os
import json
import uuid
from typing import Dict, Any

import joblib
from sklearn.ensemble import IsolationForest

from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import MLModel, MLModelEvaluation
from server.modules.ml.datasets import load_feature_dataset


async def train_isolation_forest(
    db: AsyncSession,
    account_id: int,
    model_name: str = "isolation_forest",
) -> Dict[str, Any]:
    if not settings.ML_TRAINING_ENABLED:
        return {"status": "skipped", "reason": "disabled"}

    X, feature_keys = await load_feature_dataset(db, account_id)
    if X.shape[0] < settings.ML_TRAINING_MIN_SAMPLES:
        return {"status": "skipped", "reason": "insufficient_samples", "samples": X.shape[0]}

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    scores = model.decision_function(X)
    metrics = {
        "sample_count": int(X.shape[0]),
        "score_mean": float(scores.mean()),
        "score_std": float(scores.std()),
        "score_min": float(scores.min()),
        "score_max": float(scores.max()),
        "score_p05": float(_percentile(scores, 5)),
        "score_p95": float(_percentile(scores, 95)),
    }

    os.makedirs(settings.MODEL_ARTIFACT_DIR, exist_ok=True)
    artifact_path = os.path.join(
        settings.MODEL_ARTIFACT_DIR,
        f"{account_id}-{model_name}-{uuid.uuid4().hex}.joblib",
    )
    joblib.dump({"model": model, "feature_keys": feature_keys}, artifact_path)

    ml_model = MLModel(
        account_id=account_id,
        name=model_name,
        version="1.0.0",
        status="SHADOW",
        metrics=metrics,
        artifact_path=artifact_path,
        feature_keys=feature_keys,
    )
    db.add(ml_model)
    await db.flush()

    eval_row = MLModelEvaluation(
        account_id=account_id,
        model_id=ml_model.id,
        sample_count=X.shape[0],
        metrics=metrics,
    )
    db.add(eval_row)

    return {"status": "trained", "model_id": ml_model.id, "metrics": metrics}


def _percentile(arr, p: int) -> float:
    if len(arr) == 0:
        return 0.0
    return float(sorted(arr)[int(len(arr) * p / 100)])
