import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from server.config import settings
from server.modules.ingestion.dead_letter import redact_dead_letter_error, redact_dead_letter_payload
from server.modules.ingestion.processors import process_stream_lines, process_http_traffic, process_event_batch
from server.modules.persistence.database import AsyncSessionLocal
from server.models.core import IngestionJob, IngestionDeadLetter
from sqlalchemy import update

logger = logging.getLogger(__name__)


@dataclass
class IngestionJobItem:
    job_id: str
    account_id: int
    job_type: str
    payload: Dict[str, Any]


class IngestionQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[IngestionJobItem] = asyncio.Queue(
            maxsize=settings.INGESTION_QUEUE_MAX_SIZE
        )
        self._workers: list[asyncio.Task] = []
        self._running = False

    def size(self) -> int:
        return self._queue.qsize()

    def max_size(self) -> int:
        return self._queue.maxsize

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for i in range(settings.INGESTION_WORKERS):
            self._workers.append(asyncio.create_task(self._worker_loop(i)))

    async def stop(self) -> None:
        self._running = False
        for _ in self._workers:
            await self._queue.put(IngestionJobItem("stop", 0, "stop", {}))
        for t in self._workers:
            try:
                await t
            except Exception:
                pass
        self._workers.clear()

    async def enqueue(self, item: IngestionJobItem, timeout_sec: float = 0.1) -> bool:
        try:
            await asyncio.wait_for(self._queue.put(item), timeout=timeout_sec)
            return True
        except asyncio.TimeoutError:
            return False

    async def _worker_loop(self, worker_id: int) -> None:
        while self._running:
            item = await self._queue.get()
            if item.job_type == "stop":
                self._queue.task_done()
                break
            try:
                if item.job_type == "stream_lines":
                    await process_stream_lines(item.job_id, item.account_id, item.payload)
                elif item.job_type == "http_traffic":
                    await process_http_traffic(item.job_id, item.account_id, item.payload)
                elif item.job_type == "event_batch":
                    await process_event_batch(item.job_id, item.account_id, item.payload)
                else:
                    logger.warning(
                        "ingest_unknown_job",
                        extra={"job_type": item.job_type, "job_id": item.job_id},
                    )
            except Exception as exc:
                safe_error = redact_dead_letter_error(str(exc))
                logger.error(
                    "ingest_worker_failed",
                    extra={
                        "job_type": item.job_type,
                        "job_id": item.job_id,
                        "error": safe_error,
                        "error_type": type(exc).__name__,
                    },
                )
                try:
                    async with AsyncSessionLocal() as db:
                        await db.execute(
                            update(IngestionJob)
                            .where(IngestionJob.id == item.job_id)
                            .values(status="FAILED", error_count=1, error_message=safe_error)
                        )
                        db.add(IngestionDeadLetter(
                            job_id=item.job_id,
                            account_id=item.account_id,
                            payload=redact_dead_letter_payload(item.payload),
                            error_message=safe_error,
                        ))
                        await db.commit()
                except Exception:
                    pass
            finally:
                self._queue.task_done()


ingestion_queue = IngestionQueue()
