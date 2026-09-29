"""Cold-store archiver for RequestLog and EvidenceRecord."""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import uuid
import datetime
from typing import Dict, Any, Iterable

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
import boto3

from server.config import settings
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.models.core import Account, RequestLog, EvidenceRecord, TenantRetentionPolicy
from server.modules.pentest.artifact_retention import delete_expired_pentest_artifacts
from server.modules.tenancy.context import set_current_account_id

logger = logging.getLogger(__name__)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _archive_path(account_id: int, subdir: str, day: datetime.date) -> str:
    base = settings.ARCHIVE_DIR
    path = os.path.join(base, f"account_{account_id}", subdir,
                        str(day.year), f"{day.month:02d}", f"{day.day:02d}.jsonl.gz")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def _s3_key(account_id: int, subdir: str, day: datetime.date) -> str:
    return f"account_{account_id}/{subdir}/{day.year}/{day.month:02d}/{day.day:02d}.jsonl.gz"


def _upload_to_s3(path: str, key: str) -> None:
    if not settings.ARCHIVE_BUCKET:
        return
    s3 = boto3.client("s3", region_name=settings.ARCHIVE_REGION or None)
    s3.upload_file(path, settings.ARCHIVE_BUCKET, key)


def _serialize_request_log(row: RequestLog) -> Dict[str, Any]:
    return {
        "id": row.id,
        "account_id": row.account_id,
        "endpoint_id": row.endpoint_id,
        "source_ip": row.source_ip,
        "method": row.method,
        "path": row.path,
        "response_code": row.response_code,
        "response_time_ms": row.response_time_ms,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _serialize_evidence(row: EvidenceRecord) -> Dict[str, Any]:
    return {
        "id": row.id,
        "account_id": row.account_id,
        "evidence_type": row.evidence_type,
        "ref_id": row.ref_id,
        "endpoint_id": row.endpoint_id,
        "severity": row.severity,
        "summary": row.summary,
        "details": row.details,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _get_retention_days(db: AsyncSession, account_id: int) -> int:
    result = await db.execute(
        select(TenantRetentionPolicy).where(TenantRetentionPolicy.account_id == account_id)
    )
    policy = result.scalar_one_or_none()
    if policy and policy.retention_period_days:
        return int(policy.retention_period_days)
    return settings.RETENTION_DELETE_AFTER_DAYS


async def archive_once(account_id: int) -> Dict[str, Any]:
    """Archive and delete old records for a tenant."""
    if not settings.ARCHIVE_ENABLED:
        return {"status": "skipped", "reason": "disabled"}

    now = _now()
    cutoff = now - datetime.timedelta(days=settings.ARCHIVE_AFTER_DAYS)
    deleted_cutoff = now - datetime.timedelta(days=settings.RETENTION_DELETE_AFTER_DAYS)
    archived = {"request_logs": 0, "evidence_records": 0, "pentest_artifacts": 0, "pentest_artifacts_retained": 0}

    async with AsyncSessionLocal() as db:
        try:
            set_current_account_id(account_id)
            await apply_tenant_context(db)
            retention_days = await _get_retention_days(db, account_id)
            deleted_cutoff = now - datetime.timedelta(days=retention_days)

            archived["request_logs"] += await _archive_table(
                db, RequestLog, account_id, cutoff, deleted_cutoff, "request_logs", _serialize_request_log
            )
            archived["evidence_records"] += await _archive_table(
                db, EvidenceRecord, account_id, cutoff, deleted_cutoff, "evidence_records", _serialize_evidence
            )
            artifact_result = await delete_expired_pentest_artifacts(db, account_id=account_id, now=now)
            archived["pentest_artifacts"] = int(artifact_result["deleted"])
            archived["pentest_artifacts_retained"] = int(artifact_result["retained_referenced"])
            await db.commit()
        finally:
            set_current_account_id(None)

    return {"status": "ok", "archived": archived}


async def _archive_table(
    db: AsyncSession,
    model: Any,
    account_id: int,
    archive_cutoff: datetime.datetime,
    delete_cutoff: datetime.datetime,
    subdir: str,
    serializer,
) -> int:
    total_archived = 0
    while True:
        result = await db.execute(
            select(model)
            .where(
                model.account_id == account_id,
                model.created_at < archive_cutoff,
            )
            .order_by(model.created_at.asc())
            .limit(settings.ARCHIVE_BATCH_SIZE)
        )
        rows = result.scalars().all()
        if not rows:
            break

        # Group rows by day for archive files
        by_day: Dict[datetime.date, list] = {}
        for row in rows:
            day = (row.created_at or _now()).date()
            by_day.setdefault(day, []).append(row)

        for day, day_rows in by_day.items():
            path = _archive_path(account_id, subdir, day)
            with gzip.open(path, "at", encoding="utf-8") as fh:
                for row in day_rows:
                    fh.write(json.dumps(serializer(row)) + "\n")
            _upload_to_s3(path, _s3_key(account_id, subdir, day))

        ids = [row.id for row in rows]
        await db.execute(delete(model).where(model.id.in_(ids)))
        total_archived += len(rows)

    # Hard delete old records beyond retention cutoff (in case archive disabled before)
    await db.execute(
        delete(model).where(
            model.account_id == account_id,
            model.created_at < delete_cutoff,
        )
    )
    return total_archived


class ArchiveProcessor:
    def __init__(self, interval_sec: int = 3600, account_id: int = 0):
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
                logger.exception("archive_processor_error: %s", exc)
            await asyncio.sleep(self.interval)

    async def _resolve_account_ids(self) -> list[int]:
        if self.account_id > 0:
            return [self.account_id]

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Account.id).order_by(Account.id.asc()))
            return [row[0] for row in result.all()]

    async def _process_once(self) -> None:
        account_ids = await self._resolve_account_ids()
        for account_id in account_ids:
            await archive_once(account_id)
