from __future__ import annotations

from typing import Any

from server.config import settings

from ..models import DetectionEnvelope, DetectionSignal


def build_signal(
    envelope: DetectionEnvelope,
    *,
    detector_id: str,
    incident_type: str,
    category: str,
    severity: str,
    confidence: float,
    summary: str,
    tags: list[str] | None = None,
    scores: dict[str, float] | None = None,
    evidence: dict[str, Any] | None = None,
    suggested_actions: list[str] | None = None,
) -> DetectionSignal:
    return DetectionSignal(
        detector_id=detector_id,
        incident_type=incident_type,
        category=category,
        severity=severity,
        confidence=max(0.0, min(float(confidence), 1.0)),
        summary=summary,
        actor_id=envelope.actor_id,
        source_ip=envelope.source_ip,
        endpoint_id=envelope.endpoint_id,
        endpoint_scope=envelope.endpoint_scope,
        tags=tags or [],
        scores=scores or {},
        evidence=evidence or {},
        suggested_actions=suggested_actions or [],
    )


def target_text(envelope: DetectionEnvelope) -> str:
    parts = [
        envelope.path,
        " ".join(f"{k}:{v}" for k, v in envelope.request_headers.items()),
        envelope.request_body_text,
        envelope.response_body_text,
    ]
    return " ".join(part for part in parts if part)


def role_is_privileged(role: str | None) -> bool:
    return str(role or "").upper() in {"ADMIN", "SECURITY_ENGINEER", "PLATFORM_ADMIN"}


def is_admin_path(path: str) -> bool:
    lowered = path.lower()
    return any(part in lowered for part in ("/admin", "/internal", "/root", "/manage"))


def burst_threshold() -> int:
    return max(settings.DETECTION_BURST_THRESHOLD, 1)
