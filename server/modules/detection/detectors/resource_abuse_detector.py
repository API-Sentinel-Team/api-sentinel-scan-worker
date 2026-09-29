from __future__ import annotations

import json

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class ResourceAbuseDetector:
    detector_id = "resource_abuse"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Resource Abuse Detector",
            description="Detects oversized pagination, payloads, and batch amplification patterns.",
            tags=["owasp", "api4"],
            threshold_keys=["DETECTION_BATCH_LIMIT", "DETECTION_MAX_QUERY_PAGE_SIZE"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        signals: list[DetectionSignal] = []
        query = envelope.query_params or {}
        for key in ("limit", "page_size", "size"):
            if key in query:
                try:
                    value = int(query[key])
                except Exception:
                    continue
                if value > settings.DETECTION_MAX_QUERY_PAGE_SIZE:
                    signals.append(
                        build_signal(
                            envelope,
                            detector_id=cls.detector_id,
                            incident_type="alert.resource_abuse",
                            category="Resource Abuse",
                            severity="HIGH",
                            confidence=0.83,
                            summary=f"Large page size {value} requested on {envelope.path}",
                            tags=["resource", "pagination"],
                            scores={"rule": 0.83},
                            evidence={"page_size": value},
                            suggested_actions=["rate_limit"],
                        )
                    )
                    break

        if envelope.request_size > 250000:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.resource_abuse",
                    category="Large Payload",
                    severity="HIGH",
                    confidence=0.78,
                    summary=f"Large request payload ({envelope.request_size} bytes) on {envelope.path}",
                    tags=["resource", "payload"],
                    scores={"rule": 0.78},
                    evidence={"request_size": envelope.request_size},
                    suggested_actions=["rate_limit"],
                )
            )

        try:
            parsed = json.loads(envelope.request_body_text) if envelope.request_body_text else None
        except Exception:
            parsed = None
        if isinstance(parsed, list) and len(parsed) > settings.DETECTION_BATCH_LIMIT:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.resource_abuse",
                    category="Batch Amplification",
                    severity="HIGH",
                    confidence=0.86,
                    summary=f"Batch payload contained {len(parsed)} records",
                    tags=["resource", "batch"],
                    scores={"rule": 0.86},
                    evidence={"batch_count": len(parsed)},
                    suggested_actions=["rate_limit"],
                )
            )

        if state.get("path_window", {}).get("count_60s", 0) > settings.DETECTION_BURST_THRESHOLD * 2 and envelope.status_code in {413, 429}:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.resource_abuse",
                    category="Burst Resource Abuse",
                    severity="HIGH",
                    confidence=0.8,
                    summary=f"Actor repeatedly hit {envelope.path} and triggered {envelope.status_code}",
                    tags=["resource", "burst"],
                    scores={"rule": 0.8},
                    evidence={"count_60s": state.get("path_window", {}).get("count_60s", 0)},
                    suggested_actions=["rate_limit"],
                )
            )
        return signals
