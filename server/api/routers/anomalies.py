from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from server.modules.persistence.database import get_db
from server.modules.anomaly_detector.rate_detector import RateDetector
from server.modules.anomaly_detector.isolation_forest_scorer import IsolationForestScorer
from server.models.core import RequestLog

router = APIRouter()
_rate_detector = RateDetector()
_scorer = IsolationForestScorer()


@router.get("/")
async def get_anomalies(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Return recent request logs with anomaly scores."""
    result = await db.execute(
        select(RequestLog).order_by(desc(RequestLog.created_at)).limit(limit)
    )
    logs = result.scalars().all()
    return {"total": len(logs), "anomalies": [
        {
            "id": r.id,
            "endpoint_id": r.endpoint_id,
            "source_ip": r.source_ip,
            "method": r.method,
            "path": r.path,
            "response_code": r.response_code,
            "response_time_ms": r.response_time_ms,
            "created_at": str(r.created_at),
        } for r in logs
    ]}


@router.get("/rate-check")
async def check_rate(
    source_ip: str = Query(...),
    endpoint_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Check if a source IP is hitting an endpoint at anomalous rate."""
    return await _rate_detector.check_rate(source_ip, endpoint_id, db)


@router.get("/sequential-enumeration/{endpoint_id}")
async def detect_sequential_enumeration(endpoint_id: str, db: AsyncSession = Depends(get_db)):
    """Detect BOLA-style sequential ID enumeration against an endpoint."""
    return await _rate_detector.detect_sequential_enumeration(endpoint_id, db)


@router.post("/score")
async def score_request(features: dict):
    """
    Score a request for anomaly using Isolation Forest.
    Body keys: requests_per_sec, unique_paths, payload_entropy,
               param_count, error_rate, response_time_ms
    """
    score = _scorer.score(features)
    return {"anomaly_score": score, "anomalous": score > 0.7}


@router.post("/train")
async def train_model(feature_vectors: list[list]):
    """Train the Isolation Forest model on historical feature vectors."""
    _scorer.fit(feature_vectors)
    return {"status": "trained", "samples": len(feature_vectors)}


@router.post("/tune")
async def tune_anomaly_thresholds(sensitivity: float):
    global _rate_detector
    _rate_detector = RateDetector(threshold_multiplier=max(1.0, 4.0 - sensitivity * 3))
    return {"status": "tuned", "new_sensitivity": sensitivity}


@router.post("/log")
async def log_request(
    endpoint_id: str,
    source_ip: str,
    method: str,
    path: str,
    response_code: int = 200,
    response_time_ms: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single request log entry."""
    log = RequestLog(
        endpoint_id=endpoint_id,
        source_ip=source_ip,
        method=method,
        path=path,
        response_code=response_code,
        response_time_ms=response_time_ms,
    )
    db.add(log)
    await db.commit()
    return {"status": "logged", "id": log.id}
