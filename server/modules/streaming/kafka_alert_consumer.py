"""Consumes alert events from Kafka and persists to DB."""
from __future__ import annotations

import asyncio
import logging
import json
from typing import Any, Dict

try:
    from aiokafka import AIOKafkaConsumer
except Exception:  # pragma: no cover
    AIOKafkaConsumer = None

from server.config import settings
from server.models.core import Alert, EvidenceRecord
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks
from server.modules.persistence.database import AsyncSessionLocal, apply_tenant_context
from server.modules.tenancy.context import set_current_account_id

logger = logging.getLogger(__name__)


class KafkaAlertConsumer:
    def __init__(self) -> None:
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._running or not settings.KAFKA_ENABLED:
            return
        if AIOKafkaConsumer is None:
            logger.warning("kafka_alert_consumer_unavailable", reason="aiokafka missing")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        consumer = AIOKafkaConsumer(
            "events.alerts",
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            group_id=f"{settings.KAFKA_CONSUMER_GROUP_PREFIX}-alerts",
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        await consumer.start()
        try:
            async for msg in consumer:
                if not self._running:
                    break
                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                except Exception:
                    continue
                await self._handle_alert(payload)
        except Exception as exc:
            logger.error("kafka_alert_consumer_error", error=str(exc))
        finally:
            await consumer.stop()

    async def _handle_alert(self, payload: Dict[str, Any]) -> None:
        account_id = int(payload.get("account_id") or 0)
        if not account_id:
            return
        async with AsyncSessionLocal() as db:
            set_current_account_id(account_id)
            await apply_tenant_context(db)
            alert = Alert(
                account_id=account_id,
                title=payload.get("title") or payload.get("type") or "Stream Alert",
                message=payload.get("message") or payload.get("description") or "",
                severity=payload.get("severity", "MEDIUM"),
                category=payload.get("category") or payload.get("type"),
                source_ip=payload.get("source_ip"),
                endpoint=payload.get("endpoint"),
            )
            db.add(alert)
            await db.flush()
            db.add(EvidenceRecord(
                account_id=account_id,
                evidence_type="stream",
                ref_id=alert.id,
                endpoint_id=payload.get("endpoint_id"),
                severity=alert.severity,
                summary=alert.message,
                details=payload.get("evidence") or {},
            ))
            await dispatch_event(
                "alert.created",
                {
                    "id": alert.id,
                    "title": alert.title,
                    "description": alert.message,
                    "severity": alert.severity,
                    "category": alert.category,
                    "endpoint": alert.endpoint,
                },
                account_id,
                db,
            )
            await execute_playbooks(db, alert, evidence=payload.get("evidence") or {})
            await db.commit()
