from __future__ import annotations

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class BehavioralBaselineDetector:
    detector_id = "behavioral_baseline"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Behavioral Baseline Detector",
            description="Uses EWMA-style baseline drift and anomaly score deviation for actor behavior changes.",
            tags=["behavior", "baseline"],
            threshold_keys=["DETECTION_BASELINE_ZSCORE_THRESHOLD", "DETECTION_BASELINE_EWMA_ALPHA"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        profile_state = state.get("profile_state") or {}
        baseline = state.get("baseline")
        if baseline is None:
            return []
        baseline_score = float(getattr(baseline, "anomaly_score", 0.0) or 0.0)
        current_score = float(profile_state.get("anomaly_score", 0.0))
        zscore = float(state.get("response_size_zscore", 0.0))
        confidence = max(current_score, min(zscore / max(settings.DETECTION_BASELINE_ZSCORE_THRESHOLD, 0.1), 1.0))
        if current_score < 0.6 and zscore < settings.DETECTION_BASELINE_ZSCORE_THRESHOLD:
            return []
        return [
            build_signal(
                envelope,
                detector_id=cls.detector_id,
                incident_type="alert.behavioral_drift",
                category="Behavioral Drift",
                severity="MEDIUM" if confidence < 0.85 else "HIGH",
                confidence=max(confidence, baseline_score),
                summary=f"Actor behavior drift detected on {envelope.path}",
                tags=["behavior", "baseline"],
                scores={"behavioral": max(confidence, baseline_score)},
                evidence={
                    "current_anomaly_score": current_score,
                    "baseline_anomaly_score": baseline_score,
                    "response_size_zscore": zscore,
                },
            )
        ]
