from __future__ import annotations

import json
import re

from ..models import DetectionEnvelope, DetectionSignal, DetectorMetadata
from .common import build_signal

_LARGE_RESPONSE_BYTES = 1_048_576  # 1 MB

_DEBUG_PATTERNS = re.compile(
    r"Traceback \(most recent call last\)|stacktrace|StackTrace|Exception at|at line \d+|"
    r"SyntaxError:|AttributeError:|NullPointerException|java\.lang\.|Microsoft\.AspNetCore",
    re.I,
)


class SchemaValidatorDetector:
    detector_id = "schema_validator"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="API Schema Validation Detector",
            description="Detects oversized responses, missing Content-Type, malformed JSON, and debug info leakage.",
            tags=["owasp", "api3", "schema", "debug_leak"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        signals: list[DetectionSignal] = []

        # Oversized response
        if envelope.response_size > _LARGE_RESPONSE_BYTES:
            mb = round(envelope.response_size / _LARGE_RESPONSE_BYTES, 2)
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="schema_oversized_response",
                    category="data_exposure",
                    severity="MEDIUM",
                    confidence=0.7,
                    summary=f"Oversized response ({mb} MB) on {envelope.method} {envelope.path}",
                    tags=["schema", "oversized"],
                    scores={"size_mb": mb},
                    evidence={"response_size": envelope.response_size, "path": envelope.path},
                    suggested_actions=["review_pagination"],
                )
            )

        # Missing Content-Type on non-empty responses
        content_type = envelope.response_headers.get("content-type") or envelope.response_headers.get("Content-Type", "")
        if envelope.response_size > 0 and not content_type:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="schema_missing_content_type",
                    category="misconfiguration",
                    severity="LOW",
                    confidence=0.75,
                    summary=f"Missing Content-Type header on response for {envelope.method} {envelope.path}",
                    tags=["schema", "headers"],
                    scores={},
                    evidence={"path": envelope.path},
                    suggested_actions=["fix_content_type_header"],
                )
            )

        # Malformed JSON detection (only if content type claims JSON)
        if "json" in content_type.lower() and envelope.response_body_text:
            try:
                json.loads(envelope.response_body_text)
            except (json.JSONDecodeError, ValueError):
                signals.append(
                    build_signal(
                        envelope,
                        detector_id=cls.detector_id,
                        incident_type="schema_malformed_json",
                        category="misconfiguration",
                        severity="MEDIUM",
                        confidence=0.9,
                        summary=f"Malformed JSON in response body for {envelope.method} {envelope.path}",
                        tags=["schema", "json"],
                        scores={},
                        evidence={"path": envelope.path},
                        suggested_actions=["inspect_serializer"],
                    )
                )

        # Debug info / stack trace leakage
        if envelope.response_body_text and _DEBUG_PATTERNS.search(envelope.response_body_text):
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="schema_debug_info_leak",
                    category="data_exposure",
                    severity="HIGH",
                    confidence=0.92,
                    summary=f"Stack trace or debug info detected in response for {envelope.method} {envelope.path}",
                    tags=["schema", "debug_leak"],
                    scores={"rule": 0.92},
                    evidence={"path": envelope.path},
                    suggested_actions=["disable_debug_mode", "sanitize_error_responses"],
                )
            )

        return signals
