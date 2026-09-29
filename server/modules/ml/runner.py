"""ML inference runner (shadow mode with simple heuristics)."""
from __future__ import annotations

import uuid
from typing import Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import MLModelRun, Alert, EvidenceRecord
from server.modules.evidence.package import save_evidence_package
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks


def _score_simple(features: Dict[str, Any]) -> float:
    count = features.get("count", 0)
    errors = features.get("errors", 0)
    error_rate = (errors / count) if count else 0.0
    return min(1.0, error_rate * 2)


async def run_model(
    db: AsyncSession,
    account_id: int,
    model_id: str,
    actor_id: str,
    endpoint_id: str,
    features: Dict[str, Any],
    shadow: bool = True,
) -> MLModelRun:
    score = _score_simple(features)
    is_alert = (score >= settings.ML_ALERT_THRESHOLD) and not shadow
    run = MLModelRun(
        id=str(uuid.uuid4()),
        account_id=account_id,
        model_id=model_id,
        actor_id=actor_id,
        endpoint_id=endpoint_id,
        score=score,
        features=features,
        is_alert=is_alert,
    )
    db.add(run)

    if is_alert:
        alert = Alert(
            account_id=account_id,
            title="ML anomaly detected",
            message=f"Model score={score:.2f} for actor {actor_id}",
            severity="HIGH",
            category="ML",
            source_ip=actor_id,
            endpoint=endpoint_id,
        )
        db.add(alert)
        await db.flush()
        db.add(EvidenceRecord(
            account_id=account_id,
            evidence_type="ml",
            ref_id=alert.id,
            endpoint_id=endpoint_id,
            severity="HIGH",
            summary=alert.message,
            details={"score": score, "features": features, "confidence": score},
        ))
        await save_evidence_package(
            db,
            account_id,
            "ml_detection",
            alert.id,
            {"features": features, "score": score, "endpoint_id": endpoint_id},
            {"model_id": model_id, "confidence": score},
        )
        await dispatch_event(
            "alert.created",
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.message,
                "severity": alert.severity,
                "category": alert.category,
                "endpoint": alert.endpoint,
            },
            account_id,
            db,
        )
        await execute_playbooks(db, alert, evidence={"features": features})

    return run
