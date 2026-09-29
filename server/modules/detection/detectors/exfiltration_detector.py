from __future__ import annotations

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class ExfiltrationDetector:
    detector_id = "exfiltration"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Exfiltration Detector",
            description="Detects oversized responses and pagination crawl behavior suggestive of data exfiltration.",
            tags=["exfiltration", "sequence"],
            threshold_keys=["DETECTION_LARGE_RESPONSE_BYTES", "DETECTION_EXFIL_PAGE_THRESHOLD"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        signals: list[DetectionSignal] = []
        pagination = state.get("pagination_state") or {}
        zscore = state.get("response_size_zscore", 0.0)

        if envelope.response_size >= settings.DETECTION_LARGE_RESPONSE_BYTES or zscore >= settings.DETECTION_BASELINE_ZSCORE_THRESHOLD:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.exfiltration",
                    category="Large Response",
                    severity="HIGH",
                    confidence=0.84,
                    summary=f"Large response observed on {envelope.path}",
                    tags=["exfiltration", "volume"],
                    scores={"sequence": 0.84},
                    evidence={"response_size": envelope.response_size, "zscore": zscore},
                    suggested_actions=["rate_limit"],
                )
            )

        if pagination.get("distinct_pages", 0) >= settings.DETECTION_EXFIL_PAGE_THRESHOLD:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.exfiltration",
                    category="Pagination Crawl",
                    severity="HIGH",
                    confidence=0.81,
                    summary=f"Actor paged through {pagination.get('distinct_pages', 0)} result windows",
                    tags=["exfiltration", "pagination"],
                    scores={"sequence": 0.81},
                    evidence={"distinct_pages": pagination.get("distinct_pages", 0)},
                    suggested_actions=["rate_limit"],
                )
            )
        return signals
