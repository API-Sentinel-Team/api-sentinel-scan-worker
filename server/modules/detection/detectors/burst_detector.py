from __future__ import annotations

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class BurstDetector:
    detector_id = "burst"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Burst Detector",
            description="Detects request-rate bursts and slow-response anomalies.",
            tags=["behavior", "burst"],
            threshold_keys=["DETECTION_BURST_THRESHOLD", "DETECTION_SLOW_RESPONSE_THRESHOLD_MS"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        profile_state = state.get("profile_state") or {}
        rate_per_min = float(profile_state.get("rate_per_min", 0.0))
        signals: list[DetectionSignal] = []
        if rate_per_min >= settings.DETECTION_BURST_THRESHOLD:
            severity = "HIGH" if rate_per_min >= settings.DETECTION_BURST_THRESHOLD * 1.5 else "MEDIUM"
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.rate_burst",
                    category="Rate Burst",
                    severity=severity,
                    confidence=0.88 if severity == "HIGH" else 0.74,
                    summary=f"Actor reached {rate_per_min:.1f} req/min on {envelope.path}",
                    tags=["behavior", "rate"],
                    scores={"behavioral": min(rate_per_min / max(settings.DETECTION_BURST_THRESHOLD, 1), 1.0)},
                    evidence={"rate_per_min": rate_per_min},
                    suggested_actions=["rate_limit"],
                )
            )
        if envelope.latency_ms and envelope.latency_ms >= settings.DETECTION_SLOW_RESPONSE_THRESHOLD_MS:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.slow_response",
                    category="Slow Response",
                    severity="MEDIUM",
                    confidence=0.7,
                    summary=f"Slow response ({envelope.latency_ms} ms) observed on {envelope.path}",
                    tags=["behavior", "latency"],
                    scores={"behavioral": 0.7},
                    evidence={"latency_ms": envelope.latency_ms},
                )
            )
        return signals
