"""Continuous testing processor — closes the Discovery -> Testing pipeline gap.

Periodically finds newly-discovered (never-tested) endpoints and auto-enqueues a
scan for them via the existing, fully safety-checked scheduler trigger. So an
endpoint that traffic discovery just added to inventory gets tested on the next
sweep instead of waiting for a human to schedule it.

Gated by ``CONTINUOUS_TESTING_ENABLED`` (default off). Reuses TargetGuard, auth
scope, and kill-switch enforcement through ``TestScheduler._trigger_run``.
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select

from server.config import settings
from server.models.core import APIEndpoint
from server.modules.persistence.database import AsyncSessionLocal
from server.modules.scheduler.test_scheduler import TestScheduler

logger = structlog.get_logger(__name__)


class ContinuousTestingProcessor:
    def __init__(self, interval_sec: int | None = None) -> None:
        self.interval = interval_sec or settings.CONTINUOUS_TESTING_SWEEP_INTERVAL_SECONDS
        self._running = False
        self._task: asyncio.Task | None = None
        self._scheduler = TestScheduler()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        task = self._task
        self._task = None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        try:
            while self._running:
                try:
                    await self.sweep()
                except Exception as exc:  # never let the loop die
                    logger.error("continuous_testing_sweep_error", error=str(exc))
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            logger.info("continuous_testing_loop_cancelled")

    async def sweep(self) -> dict:
        """Trigger a discovery scan for each account that has untested endpoints."""
        if not settings.CONTINUOUS_TESTING_ENABLED:
            return {"status": "disabled", "accounts_triggered": 0}

        account_ids = await self._accounts_with_untested_endpoints()
        triggered = 0
        results: list[dict] = []
        for account_id in account_ids:
            try:
                result = await self._scheduler.trigger_continuous_discovery_scan(account_id)
            except Exception as exc:  # one bad account must not stop the sweep
                logger.error(
                    "continuous_testing_trigger_error", account_id=account_id, error=str(exc)
                )
                continue
            results.append({"account_id": account_id, **result})
            if result.get("status") in {"started", "queued"}:
                triggered += 1

        logger.info(
            "continuous_testing_sweep",
            accounts_checked=len(account_ids),
            accounts_triggered=triggered,
        )
        return {"status": "ok", "accounts_triggered": triggered, "results": results}

    @staticmethod
    async def _accounts_with_untested_endpoints() -> list[int]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(APIEndpoint.account_id)
                .where(APIEndpoint.last_tested.is_(None))
                .distinct()
            )
            return [row for row in result.scalars().all() if row is not None]
