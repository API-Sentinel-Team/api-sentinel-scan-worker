from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import Alert
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks

from .correlation_agent import correlation_agent
from .enforcement_agent import enforcement_agent
from .models import DetectionEnvelope, IncidentDecision
from .normalization_agent import normalization_agent
from .rule_detection_agent import rule_detection_agent
from .state_store import state_store

logger = logging.getLogger(__name__)


class UnifiedDetectionPipeline:
    def mode(self) -> str:
        mode = str(settings.UNIFIED_PIPELINE_MODE or "off").lower()
        if mode not in {"off", "shadow", "active"}:
            return "off"
        return mode

    def is_enabled(self) -> bool:
        return self.mode() in {"shadow", "active"}

    def is_active(self) -> bool:
        return self.mode() == "active"

    async def process(
        self,
        db: AsyncSession,
        *,
        account_id: int,
        source_type: str,
        raw_event: dict[str, Any],
        persist_request_log: bool = True,
        existing_endpoint_id: str | None = None,
        existing_actor_id: str | None = None,
        context_source: str | None = None,
        shadow: bool | None = None,
    ) -> dict[str, Any]:
        effective_shadow = self.mode() == "shadow" if shadow is None else shadow
        persist = not effective_shadow

        normalized = await normalization_agent.normalize(
            db,
            account_id,
            source_type,
            raw_event,
            persist_request_log=persist_request_log and persist,
            existing_endpoint_id=existing_endpoint_id,
            existing_actor_id=existing_actor_id,
            context_source=context_source,
        )
        envelope = normalized.envelope
        if not envelope.endpoint_id and source_type in {"sensor_flat", "stream_ebpf", "gateway_log", "stream_line", "nginx_log", "http_traffic"} and persist:
            envelope.endpoint_id = await normalization_agent.ensure_endpoint(
                db,
                envelope.account_id,
                envelope.method,
                envelope.path,
                envelope.host,
                envelope.protocol,
                envelope.status_code,
                envelope.observed_at_ms,
            )

        profile_state = await state_store.update_actor_profile(db, envelope, persist=persist)
        signals, state = await rule_detection_agent.detect(
            db,
            envelope,
            persist_hot_state=persist,
            profile_state=profile_state,
        )

        if effective_shadow:
            logger.info(
                "unified_pipeline_shadow",
                extra={
                    "account_id": envelope.account_id,
                    "source_type": source_type,
                    "signal_count": len(signals),
                    "categories": [signal.category for signal in signals],
                },
            )
            return {
                "envelope": envelope,
                "signals": signals,
                "decision": IncidentDecision(actor_id=envelope.actor_id, source_ip=envelope.source_ip, shadow=True, signals=signals),
                "state": state,
            }

        decision = await correlation_agent.correlate(
            db,
            envelope,
            signals,
            state,
            persist=persist,
            shadow=effective_shadow,
        )
        await enforcement_agent.apply(db, envelope, decision, persist=persist)
        await state_store.update_actor_baseline(db, envelope, signals, profile_state, persist=persist)
        await state_store.upsert_object_state(db, envelope, persist=persist)

        if decision.alert_id:
            alert = await db.scalar(select(Alert).where(Alert.id == decision.alert_id))
            if alert is not None:
                await dispatch_event(
                    "alert.created",
                    {
                        "id": alert.id,
                        "title": alert.title,
                        "description": alert.message,
                        "severity": alert.severity,
                        "category": alert.category,
                        "source_ip": alert.source_ip,
                        "endpoint": alert.endpoint,
                    },
                    envelope.account_id,
                    db,
                )
                await execute_playbooks(
                    db,
                    alert,
                    evidence={
                        "source_ips": [envelope.source_ip] if envelope.source_ip else [],
                        "signals": [signal.model_dump() for signal in signals],
                    },
                )

        return {
            "envelope": envelope,
            "signals": signals,
            "decision": decision,
            "state": state,
        }

    def meta(self) -> dict[str, Any]:
        return {
            "mode": self.mode(),
            "knowledge_pack_version": settings.DETECTION_META_VERSION,
            "detectors": [meta.model_dump() for meta in rule_detection_agent.metadata()],
            "thresholds": {
                "burst_threshold": settings.DETECTION_BURST_THRESHOLD,
                "slow_response_ms": settings.DETECTION_SLOW_RESPONSE_THRESHOLD_MS,
                "ip_block_threshold": settings.DETECTION_IP_BLOCK_THRESHOLD,
                "dedupe_seconds": settings.DETECTION_ALERT_DEDUPE_SECONDS,
                "batch_limit": settings.DETECTION_BATCH_LIMIT,
                "page_size_limit": settings.DETECTION_MAX_QUERY_PAGE_SIZE,
                "large_response_bytes": settings.DETECTION_LARGE_RESPONSE_BYTES,
            },
            "hot_state": {
                "backend": "redis+db" if settings.REDIS_URL else "db_fallback",
                "redis_configured": bool(settings.REDIS_URL),
            },
        }


unified_detection_pipeline = UnifiedDetectionPipeline()
