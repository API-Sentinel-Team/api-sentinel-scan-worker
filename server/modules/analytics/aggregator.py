"""Analytics aggregation for endpoint/actor metrics and alert stats."""
from __future__ import annotations

import uuid
import datetime
from typing import Iterable, Tuple, Dict, Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    RequestLog,
    Alert,
    EndpointMetricHourly,
    ActorMetricHourly,
    AlertMetricDaily,
)


def _hour_bucket(dt: datetime.datetime) -> int:
    hour_start = dt.replace(minute=0, second=0, microsecond=0)
    return int(hour_start.timestamp())


def _day_bucket(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%d")


async def aggregate_hourly(
    db: AsyncSession,
    account_id: int,
    hour_start: datetime.datetime,
    hour_end: datetime.datetime,
) -> None:
    # Endpoint aggregates
    stmt = (
        select(
            RequestLog.endpoint_id,
            func.count(RequestLog.id).label("reqs"),
            func.sum(case((RequestLog.response_code >= 400, 1), else_=0)).label("errors"),
            func.avg(RequestLog.response_time_ms).label("avg_latency"),
        )
        .where(
            RequestLog.account_id == account_id,
            RequestLog.created_at >= hour_start,
            RequestLog.created_at < hour_end,
        )
        .group_by(RequestLog.endpoint_id)
    )
    result = await db.execute(stmt)
    hour_ts = _hour_bucket(hour_start)
    for endpoint_id, reqs, errors, avg_latency in result.all():
        metric = await _upsert_endpoint_metric(
            db, account_id, endpoint_id, hour_ts,
            reqs or 0, errors or 0, float(avg_latency or 0.0),
        )
        # Approximate p95 from sample list (fallback)
        metric.p95_latency_ms = metric.avg_latency_ms

    # Actor aggregates
    stmt = (
        select(
            RequestLog.source_ip,
            func.count(RequestLog.id).label("reqs"),
            func.sum(case((RequestLog.response_code >= 400, 1), else_=0)).label("errors"),
            func.avg(RequestLog.response_time_ms).label("avg_latency"),
        )
        .where(
            RequestLog.account_id == account_id,
            RequestLog.created_at >= hour_start,
            RequestLog.created_at < hour_end,
        )
        .group_by(RequestLog.source_ip)
    )
    result = await db.execute(stmt)
    for actor_id, reqs, errors, avg_latency in result.all():
        await _upsert_actor_metric(
            db, account_id, actor_id, hour_ts,
            reqs or 0, errors or 0, float(avg_latency or 0.0),
        )


async def aggregate_alerts_daily(
    db: AsyncSession,
    account_id: int,
    day_start: datetime.datetime,
    day_end: datetime.datetime,
) -> None:
    stmt = (
        select(Alert.severity, func.count(Alert.id))
        .where(
            Alert.account_id == account_id,
            Alert.created_at >= day_start,
            Alert.created_at < day_end,
        )
        .group_by(Alert.severity)
    )
    result = await db.execute(stmt)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for severity, count in result.all():
        sev = (severity or "MEDIUM").upper()
        counts[sev] = counts.get(sev, 0) + (count or 0)
        total += count or 0

    day = _day_bucket(day_start)
    metric = await _get_alert_metric(db, account_id, day)
    if not metric:
        metric = AlertMetricDaily(
            id=str(uuid.uuid4()),
            account_id=account_id,
            day=day,
        )
        db.add(metric)
    metric.total = total
    metric.critical = counts.get("CRITICAL", 0)
    metric.high = counts.get("HIGH", 0)
    metric.medium = counts.get("MEDIUM", 0)
    metric.low = counts.get("LOW", 0)


async def _upsert_endpoint_metric(
    db: AsyncSession,
    account_id: int,
    endpoint_id: str | None,
    hour_ts: int,
    reqs: int,
    errors: int,
    avg_latency: float,
) -> EndpointMetricHourly:
    result = await db.execute(
        select(EndpointMetricHourly).where(
            EndpointMetricHourly.account_id == account_id,
            EndpointMetricHourly.endpoint_id == endpoint_id,
            EndpointMetricHourly.hour_ts == hour_ts,
        )
    )
    metric = result.scalar_one_or_none()
    if not metric:
        metric = EndpointMetricHourly(
            id=str(uuid.uuid4()),
            account_id=account_id,
            endpoint_id=endpoint_id,
            hour_ts=hour_ts,
        )
        db.add(metric)
    metric.request_count = reqs
    metric.error_count = errors
    metric.avg_latency_ms = avg_latency
    return metric


async def _upsert_actor_metric(
    db: AsyncSession,
    account_id: int,
    actor_id: str | None,
    hour_ts: int,
    reqs: int,
    errors: int,
    avg_latency: float,
) -> ActorMetricHourly:
    result = await db.execute(
        select(ActorMetricHourly).where(
            ActorMetricHourly.account_id == account_id,
            ActorMetricHourly.actor_id == actor_id,
            ActorMetricHourly.hour_ts == hour_ts,
        )
    )
    metric = result.scalar_one_or_none()
    if not metric:
        metric = ActorMetricHourly(
            id=str(uuid.uuid4()),
            account_id=account_id,
            actor_id=actor_id,
            hour_ts=hour_ts,
        )
        db.add(metric)
    metric.request_count = reqs
    metric.error_count = errors
    metric.avg_latency_ms = avg_latency
    return metric


async def _get_alert_metric(db: AsyncSession, account_id: int, day: str) -> AlertMetricDaily | None:
    result = await db.execute(
        select(AlertMetricDaily).where(
            AlertMetricDaily.account_id == account_id,
            AlertMetricDaily.day == day,
        )
    )
    return result.scalar_one_or_none()


async def recompute_recent(
    db: AsyncSession,
    account_id: int,
    hours: int = 24,
    days: int = 7,
) -> Dict[str, Any]:
    now = datetime.datetime.now(datetime.timezone.utc)
    for h in range(hours):
        end = now - datetime.timedelta(hours=h)
        start = end - datetime.timedelta(hours=1)
        await aggregate_hourly(db, account_id, start, end)

    for d in range(days):
        day_end = now - datetime.timedelta(days=d)
        day_start = day_end.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + datetime.timedelta(days=1)
        await aggregate_alerts_daily(db, account_id, day_start, day_end)

    return {"status": "ok", "hours": hours, "days": days}
