"""Background recon scheduler and runner."""
from __future__ import annotations

import asyncio
import datetime
import logging
import structlog
from typing import Dict, Any

from sqlalchemy import select

from server.config import settings
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.modules.recon.adapters import ReconAdapterRegistry
from server.modules.recon.processor import ReconProcessor
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks
from server.models.core import ReconSourceConfig, Alert
from server.modules.tenancy.context import set_current_account_id

logger = structlog.get_logger(__name__)


class ReconSourceRunner:
    def __init__(self) -> None:
        self.adapters = ReconAdapterRegistry()
        self.processor = ReconProcessor()

    async def run_source(self, db, source: ReconSourceConfig) -> Dict[str, Any]:
        now = datetime.datetime.now(datetime.timezone.utc)
        interval = source.interval_seconds or settings.RECON_DEFAULT_INTERVAL_SECONDS
        source.last_run_at = now
        source.next_run_at = now + datetime.timedelta(seconds=interval)

        items, error = await self.adapters.fetch_items(source)
        if error:
            source.last_status = "ERROR"
            source.last_error = error
            return {"success": False, "error": error}

        stats = await self.processor.ingest(db, source.account_id, source.provider, items)
        source.last_status = "SUCCESS"
        source.last_error = None
        if stats.get("created", 0) > 0:
            alert = Alert(
                account_id=source.account_id,
                title="Shadow endpoints detected (external recon)",
                message=f"{stats.get('created')} new shadow candidates from {source.provider}",
                severity="HIGH",
                category="SHADOW_ENDPOINT",
                endpoint=None,
            )
            db.add(alert)
            await db.flush()
            await execute_playbooks(
                db,
                alert,
                evidence={
                    "source": source.provider,
                    "stats": stats,
                },
                trigger="endpoint.shadow_detected",
            )
            await dispatch_event(
                "endpoint.shadow_detected",
                {
                    "type": "SHADOW_ENDPOINT",
                    "severity": "HIGH",
                    "source": source.provider,
                    "description": f"{stats.get('created')} new shadow candidates from {source.provider}",
                    "stats": stats,
                },
                source.account_id,
                db,
            )
        return {"success": True, "stats": stats}


class ReconScheduler:
    def __init__(self, interval_sec: int = 300) -> None:
        self.interval = interval_sec
        self._running = False
        self._task: asyncio.Task | None = None
        self._runner = ReconSourceRunner()

    async def start(self) -> None:
        if self._running or not settings.RECON_SCHEDULER_ENABLED:
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
                await self._run_due_sources()
            except Exception as exc:
                logger.error("recon_scheduler_error", error=str(exc))
            await asyncio.sleep(self.interval)

    async def _run_due_sources(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ReconSourceConfig).where(
                    ReconSourceConfig.enabled == True,
                    (ReconSourceConfig.next_run_at.is_(None))
                    | (ReconSourceConfig.next_run_at <= now),
                )
            )
            sources = result.scalars().all()
            for source in sources:
                set_current_account_id(source.account_id)
                await apply_tenant_context(db)
                await self._runner.run_source(db, source)
            await db.commit()
