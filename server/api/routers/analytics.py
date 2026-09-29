"""Analytics endpoints for aggregated metrics."""
import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from server.modules.auth.rbac import RBAC
from server.modules.persistence.database import get_read_db, get_db
from server.models.core import EndpointMetricHourly, ActorMetricHourly, AlertMetricDaily
from server.modules.analytics.aggregator import recompute_recent

router = APIRouter(tags=["Analytics"])


@router.get("/endpoints/hourly")
async def endpoint_hourly(
    endpoint_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    now = datetime.datetime.now(datetime.timezone.utc)
    start_ts = int((now - datetime.timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0).timestamp())
    filters = [
        EndpointMetricHourly.account_id == account_id,
        EndpointMetricHourly.hour_ts >= start_ts,
    ]
    if endpoint_id:
        filters.append(EndpointMetricHourly.endpoint_id == endpoint_id)
    result = await db.execute(
        select(EndpointMetricHourly)
        .where(and_(*filters))
        .order_by(EndpointMetricHourly.hour_ts.asc())
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "metrics": [
            {
                "endpoint_id": r.endpoint_id,
                "hour_ts": r.hour_ts,
                "request_count": r.request_count,
                "error_count": r.error_count,
                "avg_latency_ms": r.avg_latency_ms,
                "p95_latency_ms": r.p95_latency_ms,
            }
            for r in rows
        ],
    }


@router.get("/actors/hourly")
async def actor_hourly(
    actor_id: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    now = datetime.datetime.now(datetime.timezone.utc)
    start_ts = int((now - datetime.timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0).timestamp())
    filters = [
        ActorMetricHourly.account_id == account_id,
        ActorMetricHourly.hour_ts >= start_ts,
    ]
    if actor_id:
        filters.append(ActorMetricHourly.actor_id == actor_id)
    result = await db.execute(
        select(ActorMetricHourly)
        .where(and_(*filters))
        .order_by(ActorMetricHourly.hour_ts.asc())
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "metrics": [
            {
                "actor_id": r.actor_id,
                "hour_ts": r.hour_ts,
                "request_count": r.request_count,
                "error_count": r.error_count,
                "avg_latency_ms": r.avg_latency_ms,
            }
            for r in rows
        ],
    }


@router.get("/alerts/daily")
async def alerts_daily(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    now = datetime.datetime.now(datetime.timezone.utc)
    start_day = (now - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    result = await db.execute(
        select(AlertMetricDaily)
        .where(AlertMetricDaily.account_id == account_id, AlertMetricDaily.day >= start_day)
        .order_by(AlertMetricDaily.day.asc())
    )
    rows = result.scalars().all()
    return {
        "total": len(rows),
        "metrics": [
            {
                "day": r.day,
                "total": r.total,
                "critical": r.critical,
                "high": r.high,
                "medium": r.medium,
                "low": r.low,
            }
            for r in rows
        ],
    }


@router.post("/recompute")
async def recompute(
    hours: int = Query(24, ge=1, le=168),
    days: int = Query(7, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    account_id = payload.get("account_id")
    result = await recompute_recent(db, account_id=account_id, hours=hours, days=days)
    await db.commit()
    return result
