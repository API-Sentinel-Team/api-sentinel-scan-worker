from __future__ import annotations

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal, is_admin_path, role_is_privileged


class BFLADetector:
    detector_id = "bfla"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="BFLA Detector",
            description="Detects function-level authorization abuse via admin-path and method-escalation heuristics.",
            tags=["owasp", "api5"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        role = (envelope.role or "").upper()
        signals: list[DetectionSignal] = []
        if is_admin_path(envelope.path) and not role_is_privileged(role):
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.bfla_detected",
                    category="BFLA",
                    severity="HIGH",
                    confidence=0.84,
                    summary=f"Non-privileged role '{role or 'UNKNOWN'}' probed admin path {envelope.path}",
                    tags=["authz", "admin-path"],
                    scores={"rule": 0.84},
                    evidence={"role": role, "path": envelope.path},
                    suggested_actions=["rate_limit"],
                )
            )
        if envelope.method in {"POST", "PUT", "PATCH", "DELETE"} and role in {"VIEWER", "AUDITOR"}:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.method_escalation",
                    category="Method Escalation",
                    severity="MEDIUM",
                    confidence=0.72,
                    summary=f"Read-oriented role '{role}' used write method {envelope.method} on {envelope.path}",
                    tags=["authz", "method"],
                    scores={"rule": 0.72},
                    evidence={"role": role, "method": envelope.method},
                )
            )
        return signals
