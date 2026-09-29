from __future__ import annotations

import datetime

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class AuthAnomalyDetector:
    detector_id = "auth_anomaly"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="Auth Anomaly Detector",
            description="Detects auth-failure spikes, expired JWTs, session fixation, and suspicious geo shifts.",
            tags=["owasp", "api2", "auth"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        signals: list[DetectionSignal] = []
        metadata = envelope.metadata or {}
        baseline = state.get("baseline")
        last_country = ((baseline.metadata_blob or {}).get("last_country") if baseline else None)

        if metadata.get("auth_failure_count", 0) >= settings.STREAM_AUTH_FAILURE_THRESHOLD:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.credential_stuffing",
                    category="Credential Stuffing",
                    severity="HIGH",
                    confidence=0.9,
                    summary=f"Observed {metadata.get('auth_failure_count', 0)} auth failures on {envelope.path}",
                    tags=["auth", "aggregate"],
                    scores={"behavioral": 0.9},
                    evidence=metadata,
                    suggested_actions=["rate_limit"],
                )
            )

        exp = metadata.get("jwt_exp")
        if exp and int(exp) * 1000 < envelope.observed_at_ms:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.expired_jwt",
                    category="Expired JWT",
                    severity="MEDIUM",
                    confidence=0.74,
                    summary=f"Expired JWT used on {envelope.path}",
                    tags=["auth", "jwt"],
                    scores={"rule": 0.74},
                    evidence={"jwt_exp": exp},
                )
            )

        if "sessionid=" in envelope.path.lower() or ("cookie" in envelope.request_headers and "authorization" in envelope.request_headers):
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.session_fixation",
                    category="Session Fixation",
                    severity="MEDIUM",
                    confidence=0.68,
                    summary=f"Potential session fixation indicator on {envelope.path}",
                    tags=["auth", "session"],
                    scores={"rule": 0.68},
                    evidence={"headers": list(envelope.request_headers.keys())[:10]},
                )
            )

        if envelope.geo_country and last_country and envelope.geo_country != last_country:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.geo_impossible",
                    category="Geo Anomaly",
                    severity="LOW",
                    confidence=0.55,
                    summary=f"Actor country changed from {last_country} to {envelope.geo_country}",
                    tags=["auth", "geo"],
                    scores={"behavioral": 0.55},
                    evidence={"previous_country": last_country, "current_country": envelope.geo_country},
                )
            )
        return signals
