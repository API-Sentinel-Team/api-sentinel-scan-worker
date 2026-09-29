from __future__ import annotations

import re

from ..models import DetectionEnvelope, DetectionSignal, DetectorMetadata
from .common import build_signal

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("phone", re.compile(r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I)),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]


class SensitiveDataDetector:
    detector_id = "sensitive_data"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Sensitive Data Exposure Detector",
            description="Detects PII, credentials, and financial data in API responses.",
            tags=["owasp", "api2", "pii", "data_exposure"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        text = envelope.response_body_text
        if not text:
            return []

        matches: list[tuple[str, str]] = []
        for label, pattern in _PATTERNS:
            found = pattern.findall(text)
            for hit in found[:5]:
                matches.append((label, str(hit)[:40]))

        if not matches:
            return []

        count = len(matches)
        severity = "HIGH" if count > 3 else "MEDIUM"
        types_found = list({m[0] for m in matches})

        return [
            build_signal(
                envelope,
                detector_id=cls.detector_id,
                incident_type="sensitive_data_exposure",
                category="data_exposure",
                severity=severity,
                confidence=0.85,
                summary=f"Sensitive data exposed in response: {', '.join(types_found)} ({count} matches) on {envelope.method} {envelope.path}",
                tags=["pii", "data_exposure"] + types_found,
                scores={"match_count": float(count)},
                evidence={"match_types": types_found, "match_count": count, "path": envelope.path},
                suggested_actions=["mask_response", "alert_data_owner"],
            )
        ]
