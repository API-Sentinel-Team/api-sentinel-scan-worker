"""Background analytics processor for near-real-time aggregates."""
from __future__ import annotations

import asyncio
import datetime
import logging

from sqlalchemy import select

from server.models.core import Account
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.modules.analytics.aggregator import aggregate_hourly, aggregate_alerts_daily
from server.modules.tenancy.context import set_current_account_id

logger = logging.getLogger(__name__)


class AnalyticsProcessor:
    def __init__(self, interval_sec: int = 60, account_id: int = 0):
        self.interval = interval_sec
        self.account_id = account_id
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._process_once()
            except Exception as exc:
                logger.exception("analytics_processor_error: %s", exc)
            await asyncio.sleep(self.interval)

    async def _resolve_account_ids(self) -> list[int]:
        if self.account_id > 0:
            return [self.account_id]

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Account.id).order_by(Account.id.asc()))
            return [row[0] for row in result.all()]

    async def _process_account(
        self,
        account_id: int,
        hour_start: datetime.datetime,
        hour_end: datetime.datetime,
        day_start: datetime.datetime,
        day_end: datetime.datetime,
    ) -> None:
        async with AsyncSessionLocal() as db:
            try:
                set_current_account_id(account_id)
                await apply_tenant_context(db)
                await aggregate_hourly(db, account_id, hour_start, hour_end)
                await aggregate_alerts_daily(db, account_id, day_start, day_end)
                await db.commit()
            finally:
                set_current_account_id(None)

    async def _process_once(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        hour_end = now.replace(minute=0, second=0, microsecond=0)
        hour_start = hour_end - datetime.timedelta(hours=1)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + datetime.timedelta(days=1)

        account_ids = await self._resolve_account_ids()
        for account_id in account_ids:
            await self._process_account(account_id, hour_start, hour_end, day_start, day_end)
