"""Actor behavior modeling & simple detection rules."""
from __future__ import annotations

import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import ActorProfile, Alert, EvidenceRecord
from server.modules.evidence.package import save_evidence_package
from server.modules.integrations.dispatcher import dispatch_event
from server.modules.response.playbook_executor import execute_playbooks
from server.modules.response.incident_orchestrator import handle_incident
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.ingestion.redaction import redact_ingestion_path


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


async def update_actor_profile(
    db: AsyncSession,
    account_id: int,
    actor_id: str,
    endpoint_id: Optional[str],
    timestamp_ms: int,
    response_ms: Optional[int],
) -> tuple[ActorProfile, float, datetime.datetime]:
    stmt = (
        select(ActorProfile)
        .where(ActorProfile.account_id == account_id, ActorProfile.actor_id == actor_id)
    )
    result = await db.execute(stmt)
    profile = result.scalar_one_or_none()
    now = datetime.datetime.fromtimestamp(timestamp_ms / 1000, tz=datetime.timezone.utc)

    if not profile:
        profile = ActorProfile(
            actor_id=actor_id,
            account_id=account_id,
            endpoint_id=endpoint_id,
            first_seen=now,
            window_start=now,
        )
        db.add(profile)
        await db.flush()

    window_start = profile.window_start or now
    if window_start and window_start.tzinfo is None:
        window_start = window_start.replace(tzinfo=datetime.timezone.utc)
    elapsed = (now - window_start).total_seconds() or 0.0001
    if elapsed >= settings.DETECTION_WINDOW_SECONDS:
        profile.recent_events = 0
        profile.window_start = now
        elapsed = 0.0001

    profile.total_events = (profile.total_events or 0) + 1
    profile.recent_events = (profile.recent_events or 0) + 1
    profile.last_seen = now
    profile.endpoint_id = endpoint_id

    if response_ms:
        total_events = profile.total_events or 1
        prev_total_ms = profile.avg_response_ms * (total_events - 1)
        profile.avg_response_ms = (prev_total_ms + response_ms) / total_events

    rate_per_min = (profile.recent_events / elapsed) * 60
    profile.anomaly_score = min(1.0, rate_per_min / (settings.DETECTION_BURST_THRESHOLD or 1))
    return profile, rate_per_min, now


async def detect_api_behavior(
    db: AsyncSession,
    account_id: int,
    actor_id: str,
    endpoint_id: str | None,
    path: str,
    timestamp_ms: int,
    latency_ms: Optional[int],
):
    if not actor_id:
        return

    if unified_detection_pipeline.is_enabled():
        return await unified_detection_pipeline.process(
            db,
            account_id=account_id,
            source_type="stream_enriched",
            raw_event={
                "endpoint_id": endpoint_id,
                "actor_id": actor_id,
                "path": path,
                "method": "GET",
                "response_code": 200,
                "timestamp_ms": timestamp_ms,
                "latency_ms": latency_ms,
                "protocol": "HTTP/1.1",
                "detection_processed": False,
            },
            persist_request_log=False,
            existing_endpoint_id=endpoint_id,
            existing_actor_id=actor_id,
            context_source="LEGACY_ENGINE",
            shadow=(unified_detection_pipeline.mode() == "shadow"),
        )

    profile, rate_per_min, now = await update_actor_profile(
        db,
        account_id,
        actor_id,
        endpoint_id,
        timestamp_ms,
        latency_ms,
    )

    reason = None
    severity = "MEDIUM"
    confidence = 0.6
    signals = []

    if rate_per_min >= settings.DETECTION_BURST_THRESHOLD:
        last_alert = profile.last_alert_at
        if last_alert and last_alert.tzinfo is None:
            last_alert = last_alert.replace(tzinfo=datetime.timezone.utc)
        if last_alert and (now - last_alert).total_seconds() < settings.DETECTION_ALERT_COOLDOWN_SECONDS:
            return
        severity = "HIGH" if rate_per_min >= settings.DETECTION_BURST_THRESHOLD * 1.5 else "MEDIUM"
        reason = f"Actor {actor_id} hammered {rate_per_min:.1f} req/min"
        signals.append("rate_burst")
        confidence = 0.9 if rate_per_min >= settings.DETECTION_BURST_THRESHOLD * 2 else 0.75

    elif latency_ms and latency_ms >= settings.DETECTION_SLOW_RESPONSE_THRESHOLD_MS:
        reason = f"Slow response {latency_ms} ms on {path}"
        severity = "MEDIUM"
        signals.append("slow_response")
        confidence = 0.8 if latency_ms >= settings.DETECTION_SLOW_RESPONSE_THRESHOLD_MS * 2 else 0.6

    if not reason:
        return

    safe_path = redact_ingestion_path(path)
    safe_reason = reason.replace(path, safe_path)

    alert = Alert(
        account_id=account_id,
        title="Behavioral anomaly detected",
        message=safe_reason,
        severity=severity,
        category="BEHAVIOR",
        source_ip=actor_id,
        endpoint=safe_path,
    )
    db.add(alert)
    await db.flush()

    db.add(EvidenceRecord(
        account_id=account_id,
        evidence_type="detection",
        ref_id=alert.id,
        endpoint_id=endpoint_id,
        severity=severity,
        summary=reason,
        details={
            "rate_per_min": rate_per_min,
            "latency_ms": latency_ms,
            "path": path,
            "confidence": confidence,
            "signals": signals,
        },
    ))
    await save_evidence_package(
        db,
        account_id,
        "behavior_detection",
        alert.id,
        {
            "actor_id": actor_id,
            "path": path,
            "rate_per_min": rate_per_min,
            "latency_ms": latency_ms,
        },
        {"reason": reason, "confidence": confidence, "signals": signals},
    )

    profile.last_alert_at = now
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
        account_id,
        db,
    )

    # Route through incident orchestrator for unified response handling
    incident_type = "alert.rate_burst" if "rate_burst" in signals else "alert.slow_response"
    await handle_incident(
        db,
        account_id,
        incident_type,
        severity,
        actor_id,
        endpoint_id,
        {"reason": reason, "confidence": confidence, "signals": signals},
    )
