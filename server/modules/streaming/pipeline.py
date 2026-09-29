"""Stream processing pipeline for enriched API events."""
from __future__ import annotations

import asyncio
import datetime
import logging
import uuid
from collections import defaultdict
from typing import Dict, Any, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.modules.persistence.database import AsyncSessionLocal
from server.models.core import Alert, EvidenceRecord, EndpointMetricHourly, ActorMetricHourly
from server.modules.evidence.package import save_evidence_package
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks
from server.modules.streaming.actor_baseline import upsert_actor_baseline
from server.modules.streaming.event_bus import get_event_bus, tenant_topic
from server.modules.streaming.schema_registry import get_registry
from server.modules.ml.feature_store import update_feature_vector
from server.modules.ml.model_registry import ensure_default_models, list_models
from server.modules.ml.runner import run_model
from server.modules.detection.pipeline import unified_detection_pipeline

logger = logging.getLogger(__name__)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hour_bucket(ts_ms: int) -> int:
    dt = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc)
    dt = dt.replace(minute=0, second=0, microsecond=0)
    return int(dt.timestamp())


class SlidingCounter:
    """Simple sliding window counter with distinct actors."""
    def __init__(self, window_seconds: int = 60) -> None:
        self.window = window_seconds
        self.buckets: Dict[int, Dict[Tuple[int, str], Dict[str, Any]]] = defaultdict(dict)

    def add(self, account_id: int, endpoint_id: str, actor_id: str, ts_ms: int) -> Dict[str, Any]:
        window_start = int((ts_ms / 1000) // self.window) * self.window
        key = (account_id, endpoint_id)
        bucket = self.buckets[window_start].setdefault(key, {"count": 0, "actors": set()})
        bucket["count"] += 1
        bucket["actors"].add(actor_id)
        return {"window_start": window_start, "count": bucket["count"], "actors": bucket["actors"]}

    def cleanup(self, ts_ms: int) -> None:
        current = int((ts_ms / 1000) // self.window) * self.window
        for w in list(self.buckets.keys()):
            if w < current - self.window:
                self.buckets.pop(w, None)


class StreamPipeline:
    def __init__(self) -> None:
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._bus = get_event_bus()
        self._registry = get_registry()
        self._failure_counter = SlidingCounter(window_seconds=60)
        self._last_alert: Dict[Tuple[int, str], float] = {}
        self._metrics_cache: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
        self._models_ready: set[int] = set()

    async def start(self) -> None:
        if self._running or not settings.STREAM_PROCESSING_ENABLED:
            return
        if settings.STREAM_ENGINE.upper() != "IN_PROCESS":
            return
        self._running = True
        self._tasks.append(asyncio.create_task(self._monitor_topics()))

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()

    async def _monitor_topics(self) -> None:
        """Subscribe to per-tenant enriched topics dynamically."""
        while self._running:
            topics = [t for t in self._bus.topics() if t.startswith("events.enriched.")]
            for topic in topics:
                if not any(getattr(t, "topic", None) == topic for t in self._tasks):
                    task = asyncio.create_task(self._consume_topic(topic))
                    task.topic = topic  # type: ignore[attr-defined]
                    self._tasks.append(task)
            await asyncio.sleep(2.0)

    async def _consume_topic(self, topic: str) -> None:
        async for event in self._bus.subscribe(topic):
            await self._handle_event(event)

    async def _handle_event(self, event: Dict[str, Any]) -> None:
        ok, err = self._registry.validate("EnrichedEvent", "1.0", event)
        if not ok:
            logger.warning("stream_event_invalid", error=err)
            return

        account_id = event["account_id"]
        endpoint_id = event["endpoint_id"]
        actor_id = event.get("actor_id", "")
        response_code = event.get("response_code", 200)
        ts_ms = event.get("timestamp_ms", int(_now().timestamp() * 1000))
        latency = event.get("latency_ms")
        quality = event.get("quality_score")
        if quality is not None and quality < settings.STREAM_MIN_QUALITY_SCORE:
            return

        if unified_detection_pipeline.is_enabled() and not event.get("detection_processed"):
            async with AsyncSessionLocal() as db:
                await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="stream_enriched",
                    raw_event=event,
                    persist_request_log=False,
                    existing_endpoint_id=endpoint_id,
                    existing_actor_id=actor_id,
                    context_source="STREAM_ENRICHED",
                    shadow=(unified_detection_pipeline.mode() == "shadow"),
                )
                if unified_detection_pipeline.is_active():
                    await db.commit()

        # Update metrics cache
        hour_ts = _hour_bucket(ts_ms)
        metric_key = (account_id, endpoint_id, hour_ts)
        metric = self._metrics_cache.setdefault(metric_key, {
            "count": 0, "errors": 0, "latency_sum": 0.0, "latency_n": 0, "actor_id": actor_id
        })
        metric["count"] += 1
        if response_code >= 400:
            metric["errors"] += 1
        if latency:
            metric["latency_sum"] += float(latency)
            metric["latency_n"] += 1

        # Sliding window auth failure detection
        if response_code in (401, 403):
            stats = self._failure_counter.add(account_id, endpoint_id, actor_id, ts_ms)
            self._failure_counter.cleanup(ts_ms)
            await self._check_credential_stuffing(account_id, endpoint_id, stats, event)

        # ML shadow mode evaluation
        try:
            async with AsyncSessionLocal() as db:
                if account_id not in self._models_ready:
                    await ensure_default_models(db, account_id)
                    self._models_ready.add(account_id)
                vec = await update_feature_vector(db, account_id, actor_id, endpoint_id, event)
                models = await list_models(db, account_id)
                for m in models:
                    await run_model(
                        db,
                        account_id=account_id,
                        model_id=m.id,
                        actor_id=actor_id,
                        endpoint_id=endpoint_id,
                        features=vec.features or {},
                        shadow=(m.status != "ACTIVE" or settings.ML_SHADOW_MODE),
                    )
                await db.commit()
        except Exception as exc:
            logger.error("ml_shadow_error", error=str(exc))

        # Periodically flush metrics (once per minute)
        if metric["count"] % 50 == 0:
            await self._flush_metrics(account_id, endpoint_id, hour_ts, metric)

    async def _check_credential_stuffing(
        self, account_id: int, endpoint_id: str, stats: Dict[str, Any], event: Dict[str, Any]
    ) -> None:
        count = stats["count"]
        actors = stats["actors"]
        if count < settings.STREAM_AUTH_FAILURE_THRESHOLD:
            return
        if len(actors) < settings.STREAM_DISTINCT_ACTORS_THRESHOLD:
            return

        key = (account_id, endpoint_id)
        last_ts = self._last_alert.get(key, 0)
        now_ts = _now().timestamp()
        if now_ts - last_ts < settings.STREAM_ALERT_SUPPRESS_SECONDS:
            return
        self._last_alert[key] = now_ts

        pipeline_mode = unified_detection_pipeline.mode()
        aggregate_event = {
            "endpoint_id": endpoint_id,
            "path": event.get("path"),
            "method": event.get("method", "POST"),
            "status_code": event.get("response_code", 401),
            "timestamp_ms": event.get("timestamp_ms"),
            "count": count,
            "distinct_actors": len(actors),
            "actor_id": "multiple",
            "source_ip": "multiple",
        }

        if pipeline_mode == "active":
            async with AsyncSessionLocal() as db:
                await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="auth_failure_aggregate",
                    raw_event=aggregate_event,
                    persist_request_log=False,
                    existing_endpoint_id=endpoint_id,
                    context_source="STREAM_AGGREGATE",
                )
                await db.commit()
            return

        if pipeline_mode == "shadow":
            async with AsyncSessionLocal() as db:
                await unified_detection_pipeline.process(
                    db,
                    account_id=account_id,
                    source_type="auth_failure_aggregate",
                    raw_event=aggregate_event,
                    persist_request_log=False,
                    existing_endpoint_id=endpoint_id,
                    context_source="STREAM_AGGREGATE",
                    shadow=True,
                )

        async with AsyncSessionLocal() as db:
            confidence = min(0.99, 0.6 + (count / max(1, settings.STREAM_AUTH_FAILURE_THRESHOLD)) * 0.2)
            alert = Alert(
                account_id=account_id,
                title="Credential stuffing suspected",
                message=f"{count} auth failures from {len(actors)} actors in 1 minute",
                severity="HIGH",
                category="CREDENTIAL_STUFFING",
                source_ip="multiple",
                endpoint=event.get("path"),
            )
            db.add(alert)
            await db.flush()
            db.add(EvidenceRecord(
                account_id=account_id,
                evidence_type="stream",
                ref_id=alert.id,
                endpoint_id=endpoint_id,
                severity="HIGH",
                summary=alert.message,
                details={
                    "count": count,
                    "distinct_actors": len(actors),
                    "endpoint_id": endpoint_id,
                    "confidence": confidence,
                },
            ))
            await save_evidence_package(
                db,
                account_id,
                "stream_credential_stuffing",
                str(alert.id),
                {"event": event, "actors": list(actors)},
                {"confidence": confidence, "distinct_actors": len(actors), "count": count},
            )
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
            await execute_playbooks(db, alert, evidence={"source_ips": list(actors)})
            await db.commit()

    async def _flush_metrics(self, account_id: int, endpoint_id: str, hour_ts: int, metric: Dict[str, Any]) -> None:
        async with AsyncSessionLocal() as db:
            avg_latency = (metric["latency_sum"] / metric["latency_n"]) if metric["latency_n"] else 0.0
            # Endpoint metrics
            em = EndpointMetricHourly(
                id=str(uuid.uuid4()),
                account_id=account_id,
                endpoint_id=endpoint_id,
                hour_ts=hour_ts,
                request_count=metric["count"],
                error_count=metric["errors"],
                avg_latency_ms=avg_latency,
                p95_latency_ms=avg_latency,
            )
            db.add(em)
            # Actor metrics
            actor_id = metric.get("actor_id", "")
            if actor_id:
                am = ActorMetricHourly(
                    id=str(uuid.uuid4()),
                    account_id=account_id,
                    actor_id=actor_id,
                    hour_ts=hour_ts,
                    request_count=metric["count"],
                    error_count=metric["errors"],
                    avg_latency_ms=avg_latency,
                )
                db.add(am)
                anomaly_score = min(1.0, float(metric["errors"]) / max(1, metric["count"]))
                await upsert_actor_baseline(
                    db,
                    account_id,
                    actor_id,
                    endpoint_id,
                    anomaly_score,
                    {"avg_latency_ms": avg_latency, "error_rate": anomaly_score},
                )
            await db.commit()
