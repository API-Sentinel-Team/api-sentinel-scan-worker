from __future__ import annotations

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal

_AUTOMATION_UA = ("python-requests", "curl/", "go-http-client", "httpie", "aiohttp", "okhttp")


class BotDetector:
    detector_id = "bot"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Bot Detector",
            description="Detects automation fingerprints and low-variance timing behavior.",
            tags=["behavior", "bot"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        headers = envelope.request_headers or {}
        ua = headers.get("user-agent", "").lower()
        timing = state.get("timing_state") or {}
        suspicious = False
        confidence = 0.55
        reasons: list[str] = []

        if not ua:
            suspicious = True
            reasons.append("missing_user_agent")
        if any(token in ua for token in _AUTOMATION_UA):
            suspicious = True
            confidence = max(confidence, 0.75)
            reasons.append("automation_user_agent")
        if not headers.get("accept-language"):
            suspicious = True
            reasons.append("missing_accept_language")
        if timing.get("count", 0) >= 5 and timing.get("stddev_gap_ms", 999999) < 50:
            suspicious = True
            confidence = max(confidence, 0.82)
            reasons.append("low_timing_variance")

        if not suspicious:
            return []
        return [
            build_signal(
                envelope,
                detector_id=cls.detector_id,
                incident_type="alert.bot_activity",
                category="Bot Activity",
                severity="MEDIUM",
                confidence=confidence,
                summary=f"Automated client indicators detected on {envelope.path}",
                tags=["behavior", "automation"],
                scores={"behavioral": confidence},
                evidence={"reasons": reasons, "timing_state": timing},
            )
        ]
