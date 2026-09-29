from __future__ import annotations

import datetime
import hashlib
import json
import math
import re
import statistics
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import ActorBaseline, ActorProfile, DetectionObjectState, ThreatActor
from server.modules.cache.redis_cache import get_json, set_json

from .models import DetectionEnvelope, DetectionSignal

_OBJECT_SEGMENT_RE = re.compile(r"(?P<id>[0-9a-f]{8,}|[0-9]{2,})", re.I)


def _from_ms(ts_ms: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc)


def _json_size(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except Exception:
        return len(str(value).encode("utf-8"))


class DetectionStateStore:
    async def update_actor_profile(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        persist: bool = True,
    ) -> dict[str, Any]:
        actor_id = envelope.actor_id or "anonymous"
        result = await db.execute(
            select(ActorProfile).where(
                ActorProfile.account_id == envelope.account_id,
                ActorProfile.actor_id == actor_id,
            )
        )
        profile = result.scalar_one_or_none()
        now = _from_ms(envelope.observed_at_ms)

        if not profile:
            profile = ActorProfile(
                actor_id=actor_id,
                account_id=envelope.account_id,
                endpoint_id=envelope.endpoint_id,
                first_seen=now,
                window_start=now,
            )
            if persist:
                db.add(profile)
                await db.flush()

        if profile.window_start and profile.window_start.tzinfo is None:
            profile.window_start = profile.window_start.replace(tzinfo=datetime.timezone.utc)

        window_start = profile.window_start or now
        elapsed = max((now - window_start).total_seconds(), 0.0001)
        recent_events = profile.recent_events or 0
        total_events = profile.total_events or 0

        if elapsed >= settings.DETECTION_WINDOW_SECONDS:
            recent_events = 0
            window_start = now
            elapsed = 0.0001

        recent_events += 1
        total_events += 1
        rate_per_min = (recent_events / elapsed) * 60
        anomaly_score = min(1.0, rate_per_min / max(settings.DETECTION_BURST_THRESHOLD, 1))

        if persist:
            profile.total_events = total_events
            profile.recent_events = recent_events
            profile.last_seen = now
            profile.window_start = window_start
            profile.endpoint_id = envelope.endpoint_id
            if envelope.latency_ms:
                previous_sum = (profile.avg_response_ms or 0.0) * max(total_events - 1, 0)
                profile.avg_response_ms = (previous_sum + envelope.latency_ms) / max(total_events, 1)
            profile.anomaly_score = anomaly_score

        return {
            "profile": profile,
            "rate_per_min": rate_per_min,
            "anomaly_score": anomaly_score,
            "now": now,
        }

    async def get_actor_timing_state(self, envelope: DetectionEnvelope, persist: bool = True) -> dict[str, Any]:
        key = f"det:timeline:{envelope.account_id}:{envelope.actor_id or 'anonymous'}"
        payload = await get_json(key) or {"timestamps": []}
        timestamps = [int(ts) for ts in payload.get("timestamps", []) if isinstance(ts, (int, float))]
        cutoff = envelope.observed_at_ms - (10 * 60 * 1000)
        timestamps = [ts for ts in timestamps if ts >= cutoff]
        if persist:
            timestamps.append(envelope.observed_at_ms)
            timestamps = timestamps[-max(settings.DETECTION_TIMING_WINDOW_SIZE, 5):]
            await set_json(key, {"timestamps": timestamps}, ttl_seconds=10 * 60)
        gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
        return {
            "timestamps": timestamps,
            "count": len(timestamps),
            "mean_gap_ms": statistics.fmean(gaps) if gaps else 0.0,
            "stddev_gap_ms": statistics.pstdev(gaps) if len(gaps) > 1 else 0.0,
        }

    async def get_path_window_state(self, envelope: DetectionEnvelope, persist: bool = True) -> dict[str, Any]:
        key = f"det:path:{envelope.account_id}:{envelope.actor_id or 'anonymous'}:{envelope.endpoint_scope or envelope.path}"
        payload = await get_json(key) or {"timestamps": []}
        timestamps = [int(ts) for ts in payload.get("timestamps", []) if isinstance(ts, (int, float))]
        cutoff_60 = envelope.observed_at_ms - (60 * 1000)
        cutoff_300 = envelope.observed_at_ms - (5 * 60 * 1000)
        timestamps = [ts for ts in timestamps if ts >= cutoff_300]
        if persist:
            timestamps.append(envelope.observed_at_ms)
            timestamps = timestamps[-100:]
            await set_json(key, {"timestamps": timestamps}, ttl_seconds=5 * 60)
        return {
            "count_60s": len([ts for ts in timestamps if ts >= cutoff_60]),
            "count_300s": len(timestamps),
        }

    async def get_pagination_state(self, envelope: DetectionEnvelope, persist: bool = True) -> dict[str, Any]:
        if not envelope.query_params:
            return {"page_markers": [], "distinct_pages": 0}
        marker = None
        for key in ("page", "offset", "cursor", "limit"):
            if key in envelope.query_params:
                marker = f"{key}={envelope.query_params[key]}"
                break
        if marker is None:
            return {"page_markers": [], "distinct_pages": 0}
        key = f"det:pages:{envelope.account_id}:{envelope.actor_id or 'anonymous'}:{envelope.endpoint_scope or envelope.path}"
        payload = await get_json(key) or {"markers": []}
        markers = [str(v) for v in payload.get("markers", [])]
        if persist:
            markers.append(marker)
            markers = markers[-50:]
            await set_json(key, {"markers": markers}, ttl_seconds=30 * 60)
        return {"page_markers": markers, "distinct_pages": len(set(markers))}

    async def get_object_window_state(self, envelope: DetectionEnvelope, persist: bool = True) -> dict[str, Any]:
        if not envelope.object_key_hash:
            return {"distinct_objects": 0, "objects": []}
        key = f"det:objects:{envelope.account_id}:{envelope.actor_id or 'anonymous'}:{envelope.endpoint_scope or envelope.path}"
        payload = await get_json(key) or {"objects": []}
        objects = [str(v) for v in payload.get("objects", [])]
        if persist:
            objects.append(envelope.object_key_hash)
            objects = objects[-50:]
            await set_json(key, {"objects": objects}, ttl_seconds=10 * 60)
        return {"distinct_objects": len(set(objects)), "objects": objects}

    async def get_actor_baseline(self, db: AsyncSession, account_id: int, actor_id: str) -> ActorBaseline | None:
        result = await db.execute(
            select(ActorBaseline).where(
                ActorBaseline.account_id == account_id,
                ActorBaseline.actor_id == actor_id,
            )
        )
        return result.scalar_one_or_none()

    async def update_actor_baseline(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        signals: list[DetectionSignal],
        profile_state: dict[str, Any],
        persist: bool = True,
    ) -> ActorBaseline | None:
        actor_id = envelope.actor_id or "anonymous"
        baseline = await self.get_actor_baseline(db, envelope.account_id, actor_id)
        ewma_alpha = settings.DETECTION_BASELINE_EWMA_ALPHA
        latest_anomaly = float(profile_state.get("anomaly_score", 0.0))
        if baseline is None:
            baseline = ActorBaseline(
                account_id=envelope.account_id,
                actor_id=actor_id,
                endpoint_history=[],
                anomaly_score=latest_anomaly,
                metadata_blob={},
                last_seen=_from_ms(envelope.observed_at_ms),
            )
            if persist:
                db.add(baseline)
                await db.flush()

        metadata = baseline.metadata_blob or {}
        prev_latency = float(metadata.get("ewma_latency_ms", envelope.latency_ms or 0.0))
        ewma_latency = (ewma_alpha * float(envelope.latency_ms or prev_latency)) + ((1 - ewma_alpha) * prev_latency)
        response_size_mean = float(metadata.get("response_size_mean", envelope.response_size or 0))
        response_size_mean = (ewma_alpha * float(envelope.response_size)) + ((1 - ewma_alpha) * response_size_mean)
        history = list(baseline.endpoint_history or [])
        if envelope.endpoint_scope:
            history.append(envelope.endpoint_scope)
        history = history[-20:]
        ewma_anomaly = (ewma_alpha * latest_anomaly) + ((1 - ewma_alpha) * float(baseline.anomaly_score or 0.0))

        if persist:
            baseline.endpoint_history = history
            baseline.anomaly_score = ewma_anomaly
            baseline.last_seen = _from_ms(envelope.observed_at_ms)
            metadata.update({
                "ewma_latency_ms": ewma_latency,
                "response_size_mean": response_size_mean,
                "last_country": envelope.geo_country,
                "last_signal_count": len(signals),
            })
            baseline.metadata_blob = metadata
        return baseline

    async def claim_dedupe_fingerprint(self, account_id: int, fingerprint: str, persist: bool = True) -> bool:
        key = f"det:dedupe:{account_id}:{fingerprint}"
        existing = await get_json(key)
        if existing is not None:
            return False
        if persist:
            await set_json(key, {"claimed": True}, ttl_seconds=settings.DETECTION_ALERT_DEDUPE_SECONDS)
        return True

    async def get_actor_reputation(self, db: AsyncSession, account_id: int, source_ip: str) -> ThreatActor | None:
        if not source_ip:
            return None
        result = await db.execute(
            select(ThreatActor).where(
                ThreatActor.account_id == account_id,
                ThreatActor.source_ip == source_ip,
            )
        )
        return result.scalar_one_or_none()

    async def get_object_state(self, db: AsyncSession, account_id: int, object_key_hash: str | None) -> DetectionObjectState | None:
        if not object_key_hash:
            return None
        result = await db.execute(
            select(DetectionObjectState).where(
                DetectionObjectState.account_id == account_id,
                DetectionObjectState.object_key_hash == object_key_hash,
            )
        )
        return result.scalar_one_or_none()

    async def upsert_object_state(self, db: AsyncSession, envelope: DetectionEnvelope, persist: bool = True) -> DetectionObjectState | None:
        if not persist or not envelope.object_key_hash:
            return None
        state = await self.get_object_state(db, envelope.account_id, envelope.object_key_hash)
        now = _from_ms(envelope.observed_at_ms)
        owner_hint = envelope.user_id or envelope.actor_id or envelope.source_ip
        if state is None:
            state = DetectionObjectState(
                account_id=envelope.account_id,
                object_key_hash=envelope.object_key_hash,
                object_key_hint=envelope.object_key,
                endpoint_scope=envelope.endpoint_scope,
                last_known_owner_actor=owner_hint,
                last_seen_actor=owner_hint,
                metadata_blob={},
                last_seen=now,
            )
            db.add(state)
            await db.flush()
            return state
        state.last_seen_actor = owner_hint
        state.last_seen = now
        if not state.last_known_owner_actor:
            state.last_known_owner_actor = owner_hint
        if envelope.endpoint_scope:
            state.endpoint_scope = envelope.endpoint_scope
        return state

    def extract_object_reference(self, envelope: DetectionEnvelope) -> tuple[str | None, str | None]:
        candidates: list[str] = []
        for key, value in (envelope.query_params or {}).items():
            if "id" in key.lower() and value not in (None, ""):
                candidates.append(str(value))
        for segment in (envelope.path or "").split("/"):
            match = _OBJECT_SEGMENT_RE.search(segment or "")
            if match:
                candidates.append(match.group("id"))
        if not candidates:
            return None, None
        raw = candidates[0]
        return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def normalize_response_size(self, envelope: DetectionEnvelope) -> int:
        return envelope.response_size or _json_size(envelope.response_body_text)

    def normalize_request_size(self, envelope: DetectionEnvelope) -> int:
        return envelope.request_size or _json_size(envelope.request_body_text)

    def response_size_zscore(self, envelope: DetectionEnvelope, baseline: ActorBaseline | None) -> float:
        if baseline is None:
            return 0.0
        metadata = baseline.metadata_blob or {}
        mean = float(metadata.get("response_size_mean", 0.0))
        if mean <= 0:
            return 0.0
        variance = max(mean * 0.5, 1.0)
        current = float(self.normalize_response_size(envelope))
        return abs(current - mean) / math.sqrt(variance)


state_store = DetectionStateStore()
