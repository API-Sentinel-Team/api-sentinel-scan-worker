from __future__ import annotations

from server.config import settings

from ..models import DetectorMetadata, DetectionEnvelope, DetectionSignal
from .common import build_signal


class BOLADetector:
    detector_id = "bola"

    @classmethod
    def metadata(cls) -> DetectorMetadata:
        return DetectorMetadata(
            detector_id=cls.detector_id,
            name="BOLA Detector",
            description="Detects object ownership mismatches and suspicious object enumeration.",
            tags=["owasp", "api1", "sequence"],
            threshold_keys=["DETECTION_OBJECT_ENUM_THRESHOLD"],
        )

    @classmethod
    def detect(cls, envelope: DetectionEnvelope, state: dict) -> list[DetectionSignal]:
        if not envelope.object_key_hash:
            return []
        signals: list[DetectionSignal] = []
        object_state = state.get("object_state")
        object_window = state.get("object_window") or {}
        actor_id = envelope.user_id or envelope.actor_id
        previous_owner = getattr(object_state, "last_known_owner_actor", None)

        if previous_owner and actor_id and previous_owner != actor_id:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.bola_detected",
                    category="BOLA",
                    severity="HIGH",
                    confidence=0.88,
                    summary=f"Actor {actor_id} accessed object previously associated with {previous_owner}",
                    tags=["sequence", "object"],
                    scores={"sequence": 0.88},
                    evidence={"object_key_hash": envelope.object_key_hash, "previous_owner": previous_owner},
                    suggested_actions=["rate_limit"],
                )
            )

        if object_window.get("distinct_objects", 0) >= settings.DETECTION_OBJECT_ENUM_THRESHOLD:
            signals.append(
                build_signal(
                    envelope,
                    detector_id=cls.detector_id,
                    incident_type="alert.object_enumeration",
                    category="Object Enumeration",
                    severity="HIGH",
                    confidence=0.82,
                    summary=f"Actor enumerated {object_window.get('distinct_objects', 0)} objects on {envelope.endpoint_scope or envelope.path}",
                    tags=["sequence", "enumeration"],
                    scores={"sequence": 0.82},
                    evidence={"distinct_objects": object_window.get("distinct_objects", 0)},
                    suggested_actions=["rate_limit"],
                )
            )

        # Only flag ownership mismatch when we have a known owner from state
        # (not just object_key != actor_id, which fires on nearly every request)
        if not signals and envelope.object_key and actor_id and object_state is not None:
            known_owner = object_state.get("last_known_owner")
            if known_owner and known_owner != actor_id and envelope.method in ("PUT", "PATCH", "DELETE"):
                signals.append(
                    build_signal(
                        envelope,
                        detector_id=cls.detector_id,
                        incident_type="alert.bola_suspected",
                        category="BOLA",
                        severity="HIGH",
                        confidence=0.70,
                        summary=f"Write to object owned by {known_owner} attempted by {actor_id} on {envelope.path}",
                        tags=["object", "ownership"],
                        scores={"sequence": 0.70},
                        evidence={"object_key": envelope.object_key, "known_owner": known_owner, "actor_id": actor_id},
                    )
                )
        return signals
