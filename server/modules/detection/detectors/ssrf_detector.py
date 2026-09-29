from __future__ import annotations

import re

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal, target_text

_SSRF_RE = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|file://|gopher://|dict://|ftp://",
    re.I,
)


class SSRFDetector:
    detector_id = "ssrf"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="SSRF Detector",
            description="Detects internal IP, metadata host, and protocol-smuggling style SSRF payloads.",
            tags=["owasp", "api7"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        text = target_text(envelope)
        if not _SSRF_RE.search(text):
            return []
        return [
            build_signal(
                envelope,
                detector_id=cls.detector_id,
                incident_type="alert.ssrf_probe",
                category="SSRF",
                severity="CRITICAL",
                confidence=0.92,
                summary=f"Possible SSRF target detected on {envelope.method} {envelope.path}",
                tags=["rule", "ssrf"],
                scores={"rule": 0.92},
                evidence={"target": _SSRF_RE.search(text).group(0) if _SSRF_RE.search(text) else ""},
                suggested_actions=["endpoint_block", "rate_limit"],
            )
        ]
