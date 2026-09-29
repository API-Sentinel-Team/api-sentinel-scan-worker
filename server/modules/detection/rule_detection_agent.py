from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .detectors import ALL_DETECTORS
from .models import DetectionEnvelope, DetectionSignal, DetectorMetadata
from .state_store import state_store


class RuleDetectionAgent:
    def __init__(self) -> None:
        self._detectors = ALL_DETECTORS

    def metadata(self) -> list[DetectorMetadata]:
        return [detector.metadata() for detector in self._detectors]

    async def build_state(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        *,
        persist_hot_state: bool = True,
        profile_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        baseline = await state_store.get_actor_baseline(db, envelope.account_id, envelope.actor_id or "anonymous")
        object_state = await state_store.get_object_state(db, envelope.account_id, envelope.object_key_hash)
        reputation = await state_store.get_actor_reputation(db, envelope.account_id, envelope.source_ip)
        timing_state = await state_store.get_actor_timing_state(envelope, persist=persist_hot_state)
        path_window = await state_store.get_path_window_state(envelope, persist=persist_hot_state)
        pagination_state = await state_store.get_pagination_state(envelope, persist=persist_hot_state)
        object_window = await state_store.get_object_window_state(envelope, persist=persist_hot_state)
        return {
            "profile_state": profile_state or {},
            "baseline": baseline,
            "object_state": object_state,
            "reputation": reputation,
            "timing_state": timing_state,
            "path_window": path_window,
            "pagination_state": pagination_state,
            "object_window": object_window,
            "response_size_zscore": state_store.response_size_zscore(envelope, baseline),
        }

    async def detect(
        self,
        db: AsyncSession,
        envelope: DetectionEnvelope,
        *,
        persist_hot_state: bool = True,
        profile_state: dict[str, Any] | None = None,
    ) -> tuple[list[DetectionSignal], dict[str, Any]]:
        state = await self.build_state(
            db,
            envelope,
            persist_hot_state=persist_hot_state,
            profile_state=profile_state,
        )
        signals: list[DetectionSignal] = []
        seen: set[tuple[str, str, str]] = set()
        for detector in self._detectors:
            for signal in detector.detect(envelope, state):
                key = (signal.detector_id, signal.category, signal.summary)
                if key in seen:
                    continue
                seen.add(key)
                signals.append(signal)
        return signals, state


rule_detection_agent = RuleDetectionAgent()
