from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import Alert, EvidenceRecord, MaliciousEvent, MaliciousEventRecord, ThreatActor
from server.modules.evidence.package import save_evidence_package
from server.modules.ingestion.redaction import redact_ingestion_path
from server.modules.utils.redactor import Redactor

from .models import IncidentDecision, SEVERITY_SCORES, DetectionEnvelope, DetectionSignal
from .state_store import state_store

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_max(signals: list[DetectionSignal]) -> str:
    highest = max(signals, key=lambda s: _SEVERITY_ORDER.get(s.severity, 0))
    return highest.severity


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _redacted_text_blob(value: str) -> str:
    redacted = Redactor.redact_json(value or "")
    if isinstance(redacted, str):
        return redacted
    return json.dumps(redacted, default=str)


def _redacted_envelope_payload(envelope: DetectionEnvelope) -> dict[str, Any]:
    payload = Redactor.redact_json(envelope.model_dump())
    if isinstance(payload, dict):
        payload["path"] = redact_ingestion_path(envelope.path)
        if envelope.endpoint_scope:
            payload["endpoint_scope"] = redact_ingestion_path(envelope.endpoint_scope)
        payload["query_params"] = {
            str(key): Redactor.REDACT_VALUE for key in (envelope.query_params or {}).keys()
        }
        payload["request_headers"] = Redactor.redact_headers(envelope.request_headers or {})
        payload["response_headers"] = Redactor.redact_headers(envelope.response_headers or {})
        payload["request_body_text"] = _redacted_text_blob(envelope.request_body_text or "")
        payload["response_body_text"] = _redacted_text_blob(envelope.response_body_text or "")
    return payload if isinstance(payload, dict) else {}


def _redacted_signal_payload(signal: DetectionSignal) -> dict[str, Any]:
    payload = Redactor.redact_json(signal.model_dump())
    return payload if isinstance(payload, dict) else {}


class CorrelationAgent:
    async def correlate(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        signals: list[DetectionSignal],
        state: dict[str, Any],
        *,
        persist: bool = True,
        shadow: bool = False,
    ) -> IncidentDecision:
        if not signals:
            return IncidentDecision(
                actor_id=envelope.actor_id,
                source_ip=envelope.source_ip,
                shadow=shadow,
            )

        primary = max(signals, key=lambda s: (_SEVERITY_ORDER.get(s.severity, 0), s.confidence))
        fingerprint = self._fingerprint(envelope, signals)
        scores = self._composite_scores(envelope, signals, state)
        risk_score = scores["composite"]

        actor = None
        if persist:
            actor = await self._upsert_threat_actor(db, envelope, risk_score, state)
            await self._persist_signal_events(db, envelope, signals, actor)

        decision = IncidentDecision(
            actor_id=envelope.actor_id,
            source_ip=envelope.source_ip,
            severity=_severity_max(signals),
            category=primary.category,
            risk_score=risk_score,
            fingerprint=fingerprint,
            signals=signals,
            scores=scores,
            shadow=shadow,
        )

        if shadow or not persist:
            return decision

        alert = await self._create_or_reuse_alert(db, envelope, signals, fingerprint)
        if alert:
            decision.alert_id = alert.id
            decision.created_alert = True
            decision.alert_title = alert.title
            safe_signals = [_redacted_signal_payload(signal) for signal in signals]
            evidence = EvidenceRecord(
                account_id=envelope.account_id,
                evidence_type="detection",
                ref_id=alert.id,
                endpoint_id=envelope.endpoint_id,
                severity=decision.severity,
                summary=alert.message,
                details={
                    "fingerprint": fingerprint,
                    "signals": safe_signals,
                    "scores": scores,
                },
            )
            db.add(evidence)
            await db.flush()
            decision.evidence_refs.append(evidence.id)
            await save_evidence_package(
                db,
                envelope.account_id,
                "unified_detection",
                alert.id,
                {
                    "envelope": _redacted_envelope_payload(envelope),
                    "signals": safe_signals,
                },
                {"scores": scores, "fingerprint": fingerprint},
            )
        return decision

    def _composite_scores(
        self,
        envelope: DetectionEnvelope,
        signals: list[DetectionSignal],
        state: dict[str, Any],
    ) -> dict[str, float]:
        def _max_component(name: str) -> float | None:
            values = [float(signal.scores.get(name, 0.0)) for signal in signals if signal.scores.get(name) is not None]
            return max(values) if values else None

        rule = _max_component("rule")
        behavioral = _max_component("behavioral")
        sequence = _max_component("sequence")

        ml_raw = envelope.metadata.get("ml_score")
        ml = float(ml_raw) if isinstance(ml_raw, (float, int)) else None

        reputation = 0.0
        reputation_actor = state.get("reputation")
        if reputation_actor is not None:
            reputation = float(reputation_actor.risk_score or 0.0)
            if reputation > 1.0:
                reputation = min(reputation / 10.0, 1.0)
            age_hours = 0.0
            if getattr(reputation_actor, "last_seen", None):
                delta = _now_utc().replace(tzinfo=None) - reputation_actor.last_seen.replace(tzinfo=None)
                age_hours = max(delta.total_seconds() / 3600, 0.0)
            reputation = reputation * (0.985 ** age_hours)

        weighted = []
        if rule is not None:
            weighted.append((rule, settings.DETECTION_RULE_WEIGHT))
        if behavioral is not None:
            weighted.append((behavioral, settings.DETECTION_BEHAVIORAL_WEIGHT))
        if ml is not None:
            weighted.append((ml, settings.DETECTION_ML_WEIGHT))
        if sequence is not None:
            weighted.append((sequence, settings.DETECTION_SEQUENCE_WEIGHT))
        if reputation > 0:
            weighted.append((reputation, settings.DETECTION_REPUTATION_WEIGHT))

        if not weighted:
            composite = max(SEVERITY_SCORES.get(signal.severity, 0.5) * signal.confidence for signal in signals)
        else:
            total_weight = sum(weight for _, weight in weighted) or 1.0
            composite = sum(value * weight for value, weight in weighted) / total_weight

        return {
            "rule": float(rule or 0.0),
            "behavioral": float(behavioral or 0.0),
            "ml": float(ml or 0.0),
            "sequence": float(sequence or 0.0),
            "reputation": float(reputation),
            "composite": min(max(composite, 0.0), 1.0),
        }

    async def _upsert_threat_actor(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        composite_score: float,
        state: dict[str, Any],
    ) -> ThreatActor:
        result = await db.execute(
            select(ThreatActor).where(
                ThreatActor.account_id == envelope.account_id,
                ThreatActor.source_ip == envelope.source_ip,
            )
        )
        actor = result.scalar_one_or_none()
        now = _now_utc().replace(tzinfo=None)
        if actor is None:
            actor = ThreatActor(
                account_id=envelope.account_id,
                source_ip=envelope.source_ip,
                status="MONITORING",
                event_count=0,
                risk_score=0.0,
            )
            db.add(actor)
            await db.flush()

        previous_risk = float(actor.risk_score or 0.0)
        if previous_risk > 1.0:
            previous_risk = min(previous_risk / 10.0, 1.0)
        if actor.last_seen:
            delta_hours = max((now - actor.last_seen.replace(tzinfo=None)).total_seconds() / 3600, 0.0)
            previous_risk = previous_risk * (0.985 ** delta_hours)

        actor.event_count = (actor.event_count or 0) + 1
        actor.risk_score = min(1.0, previous_risk + (composite_score * 0.55))
        actor.last_seen = _now_utc().replace(tzinfo=None)
        if actor.risk_score >= settings.DETECTION_IP_BLOCK_THRESHOLD:
            actor.status = "BLOCKED"
        elif actor.risk_score >= 0.5:
            actor.status = "FLAGGED"
        else:
            actor.status = "MONITORING"
        return actor

    async def _persist_signal_events(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        signals: list[DetectionSignal],
        actor: ThreatActor,
    ) -> None:
        safe_path = redact_ingestion_path(envelope.path)
        for signal in signals:
            db.add(
                MaliciousEvent(
                    account_id=envelope.account_id,
                    actor_id=actor.id,
                    event_type=signal.incident_type,
                    severity=signal.severity,
                    detected_at=_now_utc(),
                )
            )
            db.add(
                MaliciousEventRecord(
                    account_id=envelope.account_id,
                    actor=envelope.actor_id,
                    ip=envelope.source_ip,
                    url=safe_path,
                    method=envelope.method,
                    payload=_redacted_text_blob(envelope.request_body_text[:2000]),
                    event_type=signal.incident_type,
                    category=signal.category,
                    sub_category=signal.detector_id,
                    severity=signal.severity,
                    label="threat",
                    status="OPEN",
                    detected_at=envelope.observed_at_ms,
                    event_metadata={
                        "detector_id": signal.detector_id,
                        "confidence": signal.confidence,
                        "scores": signal.scores,
                    },
                    context_source=envelope.context_source,
                )
            )

    async def _create_or_reuse_alert(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        signals: list[DetectionSignal],
        fingerprint: str,
    ) -> Optional[Alert]:
        primary = max(signals, key=lambda s: (_SEVERITY_ORDER.get(s.severity, 0), s.confidence))
        safe_path = redact_ingestion_path(envelope.path)
        safe_endpoint = redact_ingestion_path(envelope.endpoint_scope or envelope.path)
        dedupe_allowed = await state_store.claim_dedupe_fingerprint(envelope.account_id, fingerprint, persist=True)
        recent_cutoff = _now_utc().replace(tzinfo=None) - datetime.timedelta(seconds=settings.DETECTION_ALERT_DEDUPE_SECONDS)
        result = await db.execute(
            select(Alert).where(
                and_(
                    Alert.account_id == envelope.account_id,
                    Alert.source_ip == envelope.source_ip,
                    Alert.category == primary.category,
                    Alert.endpoint == safe_endpoint,
                    Alert.status == "OPEN",
                    Alert.created_at >= recent_cutoff,
                )
            )
        )
        alert = result.scalar_one_or_none()
        if alert is not None:
            return alert
        if not dedupe_allowed:
            return alert

        message = "; ".join(signal.summary for signal in signals[:3])
        alert = Alert(
            account_id=envelope.account_id,
            title=f"{primary.category} detected on {envelope.method} {safe_path}",
            message=Redactor.redact_text(message),
            severity=_severity_max(signals),
            category=primary.category,
            source_ip=envelope.source_ip,
            endpoint=safe_endpoint,
            status="OPEN",
        )
        db.add(alert)
        await db.flush()
        return alert

    def _fingerprint(self, envelope: DetectionEnvelope, signals: list[DetectionSignal]) -> str:
        basis = {
            "account_id": envelope.account_id,
            "source_ip": envelope.source_ip,
            "endpoint_scope": envelope.endpoint_scope or envelope.path,
            "detectors": sorted({signal.detector_id for signal in signals}),
            "categories": sorted({signal.category for signal in signals}),
            "object_key_hash": envelope.object_key_hash,
        }
        return hashlib.sha256(json.dumps(basis, sort_keys=True).encode("utf-8")).hexdigest()


correlation_agent = CorrelationAgent()
