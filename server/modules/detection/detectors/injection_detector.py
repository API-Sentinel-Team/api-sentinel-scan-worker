from __future__ import annotations

import re

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal, target_text

_PATTERNS = [
    ("SQL Injection", "HIGH", re.compile(r"union\s+select|drop\s+table|or\s+'?1'?\s*=\s*'?1|;\s*--|sleep\s*\(|benchmark\s*\(", re.I)),
    ("XSS", "HIGH", re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(", re.I)),
    ("Path Traversal", "CRITICAL", re.compile(r"\.\./|%2e%2e%2f|/etc/passwd|/proc/self|windows/system32", re.I)),
    ("Command Injection", "CRITICAL", re.compile(r"(?:;|&&|\|)\s*(?:cat|id|whoami|curl|wget|bash|sh|powershell|cmd\.exe)", re.I)),
    ("NoSQL Injection", "HIGH", re.compile(r"\$where|\$ne|\$gt|\$regex|this\.", re.I)),
    ("Template Injection", "HIGH", re.compile(r"\{\{.*\}\}|\$\{.*\}|<%=?|__class__|mro\(", re.I)),
]


class InjectionDetector:
    detector_id = "injection"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Injection Detector",
            description="Heuristic detection for SQLi, XSS, traversal, command, NoSQL, and template injection payloads.",
            tags=["owasp", "api3", "api8"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        text = target_text(envelope)
        if envelope.metadata.get("sensor_flagged_injection"):
            return [
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.injection_detected",
                    category="Injection",
                    severity="HIGH",
                    confidence=0.95,
                    summary=f"Sensor marked request as injection on {envelope.method} {envelope.path}",
                    tags=["rule", "injection"],
                    scores={"rule": 0.95},
                    evidence={"path": envelope.path},
                    suggested_actions=["rate_limit"],
                )
            ]

        signals: list[DetectionSignal] = []
        for category, severity, pattern in _PATTERNS:
            if not pattern.search(text):
                continue
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.injection_detected",
                    category=category,
                    severity=severity,
                    confidence=0.9 if severity == "CRITICAL" else 0.8,
                    summary=f"{category} pattern matched on {envelope.method} {envelope.path}",
                    tags=["rule", "injection"],
                    scores={"rule": 0.9 if severity == "CRITICAL" else 0.8},
                    evidence={"pattern": pattern.pattern[:120], "path": envelope.path},
                    suggested_actions=["rate_limit"],
                )
            )
        return signals
