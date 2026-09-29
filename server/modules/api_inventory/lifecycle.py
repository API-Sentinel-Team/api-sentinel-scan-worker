"""Endpoint lifecycle processor for shadow/zombie status updates."""
from __future__ import annotations

import asyncio
import datetime
from collections import defaultdict

import structlog
from sqlalchemy import update, and_, select

from server.config import settings
from server.modules.persistence.database import AsyncSessionLocal
from server.models.core import APIEndpoint
from server.modules.integrations.dispatcher import dispatch_event
from server.models.core import EvidenceRecord, PolicyViolation
from server.models.core import Alert
from server.modules.response.playbook_executor import execute_playbooks

logger = structlog.get_logger(__name__)


def _as_utc_naive(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def _threshold_utc_naive() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class EndpointLifecycleProcessor:
    def __init__(self, interval_sec: int = 3600) -> None:
        self.interval = interval_sec
        self._running = False
        self._task: asyncio.Task | None = None

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
                    await self._sweep()
                except Exception as exc:
                    logger.error("lifecycle_sweep_error: %s", exc)
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            logger.info("lifecycle_loop_cancelled")

    async def _sweep(self) -> None:
        threshold = _threshold_utc_naive() - datetime.timedelta(days=settings.ZOMBIE_ENDPOINT_DAYS)
        async with AsyncSessionLocal() as db:
            endpoint_rows = await db.execute(
                select(APIEndpoint).where(
                    and_(
                        APIEndpoint.last_seen.isnot(None),
                        APIEndpoint.status != "DEPRECATED",
                    )
                )
            )
            endpoints = endpoint_rows.scalars().all()

            zombie_ids: list[str] = []
            revive_ids: list[str] = []
            zombie_map: dict[int, int] = defaultdict(int)
            revive_map: dict[int, int] = defaultdict(int)

            for endpoint in endpoints:
                last_seen = _as_utc_naive(endpoint.last_seen)
                if last_seen is None:
                    continue
                if endpoint.status == "ZOMBIE":
                    if last_seen >= threshold:
                        revive_ids.append(endpoint.id)
                        revive_map[endpoint.account_id] += 1
                    continue
                if last_seen < threshold:
                    zombie_ids.append(endpoint.id)
                    zombie_map[endpoint.account_id] += 1

            # Mark inactive endpoints as zombie
            zombie_count = 0
            if zombie_ids:
                result = await db.execute(
                    update(APIEndpoint)
                    .where(APIEndpoint.id.in_(zombie_ids))
                    .execution_options(synchronize_session=False)
                    .values(status="ZOMBIE")
                )
                zombie_count = result.rowcount or 0

            if zombie_count:
                # Add evidence records for newly zombified endpoints (sampled by threshold)
                candidates = await db.execute(
                    select(APIEndpoint)
                    .where(APIEndpoint.id.in_(zombie_ids))
                    .limit(200)
                )
                for ep in candidates.scalars().all():
                    db.add(EvidenceRecord(
                        account_id=ep.account_id,
                        evidence_type="lifecycle",
                        ref_id=ep.id,
                        endpoint_id=ep.id,
                        severity="MEDIUM",
                        summary="Endpoint marked as ZOMBIE due to inactivity",
                        details={
                            "endpoint": ep.path_pattern or ep.path,
                            "host": ep.host,
                            "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
                        },
                    ))
                    existing = await db.scalar(
                        select(PolicyViolation).where(
                            PolicyViolation.account_id == ep.account_id,
                            PolicyViolation.endpoint_id == ep.id,
                            PolicyViolation.rule_type == "ZOMBIE_ENDPOINT",
                            PolicyViolation.status == "OPEN",
                        )
                    )
                    if not existing:
                        db.add(PolicyViolation(
                            account_id=ep.account_id,
                            endpoint_id=ep.id,
                            rule_type="ZOMBIE_ENDPOINT",
                            severity="MEDIUM",
                            status="OPEN",
                            message="Endpoint marked as ZOMBIE due to inactivity",
                            violation_metadata={
                                "last_seen": ep.last_seen.isoformat() if ep.last_seen else None,
                            },
                        ))

            # Revive zombie endpoints if traffic resumes
            revived_count = 0
            if revive_ids:
                result = await db.execute(
                    update(APIEndpoint)
                    .where(APIEndpoint.id.in_(revive_ids))
                    .execution_options(synchronize_session=False)
                    .values(status="ACTIVE")
                )
                revived_count = result.rowcount or 0

            await db.commit()

            for account_id, count in zombie_map.items():
                if count:
                    alert = Alert(
                        account_id=account_id,
                        title="Zombie endpoints detected",
                        message=f"{count} endpoints marked as ZOMBIE due to inactivity",
                        severity="MEDIUM",
                        category="ZOMBIE_ENDPOINT",
                        endpoint=None,
                    )
                    db.add(alert)
                    await db.flush()
                    await execute_playbooks(
                        db,
                        alert,
                        evidence={"count": count},
                        trigger="endpoint.zombie_detected",
                    )
                    await dispatch_event(
                        "endpoint.zombie_detected",
                        {
                            "type": "ZOMBIE_ENDPOINT",
                            "severity": "MEDIUM",
                            "description": f"{count} endpoints marked as ZOMBIE",
                            "count": count,
                        },
                        account_id,
                        db,
                    )
            for account_id, count in revive_map.items():
                if count:
                    alert = Alert(
                        account_id=account_id,
                        title="Zombie endpoints revived",
                        message=f"{count} endpoints revived from ZOMBIE status",
                        severity="LOW",
                        category="ZOMBIE_REVIVED",
                        endpoint=None,
                    )
                    db.add(alert)
                    await db.flush()
                    await execute_playbooks(
                        db,
                        alert,
                        evidence={"count": count},
                        trigger="endpoint.zombie_revived",
                    )
                    await dispatch_event(
                        "endpoint.zombie_revived",
                        {
                            "type": "ZOMBIE_REVIVED",
                            "severity": "LOW",
                            "description": f"{count} endpoints revived from ZOMBIE",
                            "count": count,
                        },
                        account_id,
                        db,
                    )
                    await db.execute(
                        PolicyViolation.__table__.update()
                        .where(
                            PolicyViolation.account_id == account_id,
                            PolicyViolation.rule_type == "ZOMBIE_ENDPOINT",
                            PolicyViolation.status == "OPEN",
                        )
                        .values(status="RESOLVED")
                    )

        if zombie_count or revived_count:
            logger.info(
                "lifecycle_sweep",
                zombie_marked=zombie_count,
                zombie_revived=revived_count,
            )
