"""Exports aggregated metrics to ClickHouse warm store."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple

from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import (
    EndpointMetricHourly,
    ActorMetricHourly,
    AlertMetricDaily,
    WarmExportCursor,
)
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.modules.storage.clickhouse_client import ClickHouseClient
from server.modules.tenancy.context import set_current_account_id

logger = logging.getLogger(__name__)


class WarmStoreExporter:
    def __init__(self, interval_sec: int = 120) -> None:
        self.interval = interval_sec
        self._running = False
        self._task: asyncio.Task | None = None
        self._cursor: Dict[str, Tuple[Optional[datetime], Optional[str]]] = {
            "endpoint_metrics_hourly": (None, None),
            "actor_metrics_hourly": (None, None),
            "alert_metrics_daily": (None, None),
        }
        self._cursor_account_id = 0

    async def start(self) -> None:
        if self._running or not settings.CLICKHOUSE_ENABLED:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        ch = ClickHouseClient()
        await ch.ensure_tables()
        while self._running:
            try:
                await self._export_once(ch)
            except Exception as exc:
                logger.exception("warm_export_error: %s", exc)
            await asyncio.sleep(self.interval)

    async def _export_once(self, ch: ClickHouseClient) -> None:
        async with AsyncSessionLocal() as db:
            try:
                if self._cursor_account_id > 0:
                    set_current_account_id(self._cursor_account_id)
                    await apply_tenant_context(db)
                else:
                    set_current_account_id(None)
                await self._export_endpoint_metrics(db, ch)
                await self._export_actor_metrics(db, ch)
                await self._export_alert_metrics(db, ch)
                await db.commit()
            finally:
                set_current_account_id(None)

    async def _export_endpoint_metrics(self, db: AsyncSession, ch: ClickHouseClient) -> None:
        cursor = await self._load_cursor(db, "endpoint_metrics_hourly")
        stmt = select(EndpointMetricHourly).order_by(
            EndpointMetricHourly.created_at.asc(),
            EndpointMetricHourly.id.asc(),
        )
        if cursor[0]:
            stmt = stmt.where(
                or_(
                    EndpointMetricHourly.created_at > cursor[0],
                    and_(
                        EndpointMetricHourly.created_at == cursor[0],
                        EndpointMetricHourly.id > (cursor[1] or ""),
                    ),
                )
            )
        stmt = stmt.limit(settings.WARM_EXPORT_BATCH_SIZE)
        result = await db.execute(stmt)
        rows = result.scalars().all()
        if not rows:
            return
        payload = [{
            "account_id": r.account_id,
            "endpoint_id": r.endpoint_id or "",
            "hour_ts": r.hour_ts,
            "request_count": r.request_count,
            "error_count": r.error_count,
            "avg_latency_ms": r.avg_latency_ms,
            "p95_latency_ms": r.p95_latency_ms,
        } for r in rows]
        if await ch.insert_json_each_row("endpoint_metrics_hourly", payload):
            await self._save_cursor(
                db,
                "endpoint_metrics_hourly",
                rows[-1].created_at,
                rows[-1].id,
            )

    async def _export_actor_metrics(self, db: AsyncSession, ch: ClickHouseClient) -> None:
        cursor = await self._load_cursor(db, "actor_metrics_hourly")
        stmt = select(ActorMetricHourly).order_by(
            ActorMetricHourly.created_at.asc(),
            ActorMetricHourly.id.asc(),
        )
        if cursor[0]:
            stmt = stmt.where(
                or_(
                    ActorMetricHourly.created_at > cursor[0],
                    and_(
                        ActorMetricHourly.created_at == cursor[0],
                        ActorMetricHourly.id > (cursor[1] or ""),
                    ),
                )
            )
        stmt = stmt.limit(settings.WARM_EXPORT_BATCH_SIZE)
        result = await db.execute(stmt)
        rows = result.scalars().all()
        if not rows:
            return
        payload = [{
            "account_id": r.account_id,
            "actor_id": r.actor_id or "",
            "hour_ts": r.hour_ts,
            "request_count": r.request_count,
            "error_count": r.error_count,
            "avg_latency_ms": r.avg_latency_ms,
        } for r in rows]
        if await ch.insert_json_each_row("actor_metrics_hourly", payload):
            await self._save_cursor(
                db,
                "actor_metrics_hourly",
                rows[-1].created_at,
                rows[-1].id,
            )

    async def _export_alert_metrics(self, db: AsyncSession, ch: ClickHouseClient) -> None:
        cursor = await self._load_cursor(db, "alert_metrics_daily")
        stmt = select(AlertMetricDaily).order_by(
            AlertMetricDaily.created_at.asc(),
            AlertMetricDaily.id.asc(),
        )
        if cursor[0]:
            stmt = stmt.where(
                or_(
                    AlertMetricDaily.created_at > cursor[0],
                    and_(
                        AlertMetricDaily.created_at == cursor[0],
                        AlertMetricDaily.id > (cursor[1] or ""),
                    ),
                )
            )
        stmt = stmt.limit(settings.WARM_EXPORT_BATCH_SIZE)
        result = await db.execute(stmt)
        rows = result.scalars().all()
        if not rows:
            return
        payload = [{
            "account_id": r.account_id,
            "day": r.day,
            "total": r.total,
            "critical": r.critical,
            "high": r.high,
            "medium": r.medium,
            "low": r.low,
        } for r in rows]
        if await ch.insert_json_each_row("alert_metrics_daily", payload):
            await self._save_cursor(
                db,
                "alert_metrics_daily",
                rows[-1].created_at,
                rows[-1].id,
            )

    async def _load_cursor(
        self, db: AsyncSession, table_name: str
    ) -> Tuple[Optional[datetime], Optional[str]]:
        cached = self._cursor.get(table_name)
        if cached and (cached[0] or cached[1]):
            return cached
        result = await db.execute(
            select(WarmExportCursor)
            .where(
                WarmExportCursor.account_id == self._cursor_account_id,
                WarmExportCursor.table_name == table_name,
            )
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row:
            cursor = (row.last_created_at, row.last_id)
            self._cursor[table_name] = cursor
            return cursor
        return (None, None)

    async def _save_cursor(
        self,
        db: AsyncSession,
        table_name: str,
        last_created_at: Optional[datetime],
        last_id: Optional[str],
    ) -> None:
        result = await db.execute(
            select(WarmExportCursor)
            .where(
                WarmExportCursor.account_id == self._cursor_account_id,
                WarmExportCursor.table_name == table_name,
            )
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row:
            row.last_created_at = last_created_at
            row.last_id = last_id
        else:
            row = WarmExportCursor(
                account_id=self._cursor_account_id,
                table_name=table_name,
                last_created_at=last_created_at,
                last_id=last_id,
            )
            db.add(row)
        self._cursor[table_name] = (last_created_at, last_id)
