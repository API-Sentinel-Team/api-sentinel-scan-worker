"""Incident orchestration and automated response coordination."""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import Alert, AuditLog, ResponseActionLog
from server.modules.detection.correlation_agent import correlation_agent
from server.modules.detection.correlation_engine import correlate_threat
from server.modules.detection.enforcement_agent import enforcement_agent
from server.modules.detection.models import DetectionEnvelope, DetectionSignal
from server.modules.detection.pipeline import unified_detection_pipeline
from server.modules.detection.state_store import state_store

logger = logging.getLogger(__name__)


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _utc_now_ms() -> int:
    return int(_utc_now().timestamp() * 1000)


async def handle_incident(
    db: AsyncSession,
    account_id: int,
    incident_type: str,
    severity: str,
    source_ip: str,
    endpoint_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Handle an incident with automated threat correlation and response."""
    details = details or {}

    if unified_detection_pipeline.is_enabled():
        observed_at_ms = _utc_now_ms()
        envelope = DetectionEnvelope(
            source_type="legacy_incident",
            event_type="incident",
            account_id=account_id,
            observed_at_ms=observed_at_ms,
            actor_id=source_ip or "anonymous",
            source_ip=source_ip or "",
            method="UNKNOWN",
            path=endpoint_id or "/",
            endpoint_id=endpoint_id,
            endpoint_scope=endpoint_id or "/",
            request_body_text=str(details.get("payload_snippet") or details.get("reason") or ""),
            context_source="LEGACY_INCIDENT",
        )
        signal = DetectionSignal(
            detector_id="legacy.incident",
            incident_type=incident_type,
            category=incident_type,
            severity=severity,
            confidence=1.0,
            summary=str(details.get("reason") or f"Incident {incident_type}"),
            actor_id=envelope.actor_id,
            source_ip=envelope.source_ip,
            endpoint_id=endpoint_id,
            endpoint_scope=envelope.endpoint_scope,
            scores={"rule": 1.0},
            evidence=details,
        )
        state = {
            "profile_state": {},
            "reputation": await state_store.get_actor_reputation(db, account_id, source_ip),
        }
        decision = await correlation_agent.correlate(
            db,
            envelope,
            [signal],
            state,
            persist=(unified_detection_pipeline.mode() == "active"),
            shadow=(unified_detection_pipeline.mode() == "shadow"),
        )
        if unified_detection_pipeline.is_active():
            await enforcement_agent.apply(db, envelope, decision, persist=True)
            db.add(ResponseActionLog(
                account_id=account_id,
                alert_id=decision.alert_id,
                action_type="incident.auto_response",
                status="SUCCESS",
                details={
                    "incident_type": incident_type,
                    "severity": severity,
                    "source_ip": source_ip,
                    "risk_score": decision.risk_score,
                    "auto_blocked": decision.auto_blocked,
                    "endpoint_id": endpoint_id,
                },
            ))
            db.add(AuditLog(
                account_id=account_id,
                action="incident.auto_response",
                resource_type="incident",
                resource_id=decision.alert_id,
                details={
                    "incident_type": incident_type,
                    "severity": severity,
                    "source_ip": source_ip,
                    "auto_blocked": decision.auto_blocked,
                },
            ))
            actor = await state_store.get_actor_reputation(db, account_id, source_ip)
            return {
                "alert_id": decision.alert_id,
                "actor_id": getattr(actor, "id", envelope.actor_id),
                "actor_risk_score": float(getattr(actor, "risk_score", decision.risk_score) or decision.risk_score),
                "auto_blocked": decision.auto_blocked,
                "playbooks_executed": 1 if decision.alert_id else 0,
            }
        return {
            "alert_id": None,
            "actor_id": envelope.actor_id,
            "actor_risk_score": 0.0,
            "auto_blocked": False,
            "playbooks_executed": 0,
        }

    correlation_result = await correlate_threat(
        db=db,
        account_id=account_id,
        source_ip=source_ip,
        event_type=incident_type,
        severity=severity,
        endpoint_id=endpoint_id,
        payload_snippet=details.get("payload_snippet"),
    )

    actor_id = correlation_result["actor_id"]
    risk_score = correlation_result["risk_score"]
    auto_blocked = correlation_result["auto_blocked"]
    ten_minutes_ago = _utc_now() - datetime.timedelta(minutes=10)

    alert_result = await db.execute(
        select(Alert).where(
            and_(
                Alert.account_id == account_id,
                Alert.source_ip == source_ip,
                Alert.category == incident_type,
                Alert.status == "OPEN",
                Alert.created_at >= ten_minutes_ago,
            )
        )
    )
    alert = alert_result.scalar_one_or_none()

    if alert is None:
        alert = Alert(
            account_id=account_id,
            title=f"{severity} - {incident_type} from {source_ip}",
            message=f"Threat actor {source_ip} triggered incident: {incident_type}",
            severity=severity,
            category=incident_type,
            source_ip=source_ip,
            endpoint=endpoint_id,
            status="OPEN",
        )
        db.add(alert)
        await db.flush()
    else:
        alert.severity = severity

    db.add(ResponseActionLog(
        account_id=account_id,
        alert_id=alert.id,
        action_type="incident.auto_response",
        status="SUCCESS",
        details={
            "incident_type": incident_type,
            "severity": severity,
            "source_ip": source_ip,
            "actor_id": actor_id,
            "risk_score": risk_score,
            "auto_blocked": auto_blocked,
            "endpoint_id": endpoint_id,
        },
    ))
    db.add(AuditLog(
        account_id=account_id,
        action="incident.auto_response",
        resource_type="incident",
        resource_id=alert.id,
        details={
            "incident_type": incident_type,
            "severity": severity,
            "source_ip": source_ip,
            "auto_blocked": auto_blocked,
        },
    ))

    logger.info(
        "incident_handled",
        extra={
            "account_id": account_id,
            "incident_type": incident_type,
            "severity": severity,
            "source_ip": source_ip,
            "actor_id": actor_id,
            "risk_score": risk_score,
            "auto_blocked": auto_blocked,
            "alert_id": alert.id,
        },
    )

    return {
        "alert_id": alert.id,
        "actor_id": actor_id,
        "actor_risk_score": risk_score,
        "auto_blocked": auto_blocked,
        "playbooks_executed": 0,
    }
