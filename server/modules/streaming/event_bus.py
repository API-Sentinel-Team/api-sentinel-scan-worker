"""Event bus abstraction with in-memory and Kafka backends."""
from __future__ import annotations

import asyncio
from typing import Dict, Any, AsyncIterator, Optional, Set

from server.config import settings
from server.modules.streaming.kafka_bus import KafkaEventBus, KafkaUnavailableError


class InMemoryEventBus:
    def __init__(self) -> None:
        self._topics: Dict[str, asyncio.Queue] = {}
        self._lock = asyncio.Lock()

    async def _get_topic(self, name: str) -> asyncio.Queue:
        async with self._lock:
            if name not in self._topics:
                self._topics[name] = asyncio.Queue(maxsize=10000)
            return self._topics[name]

    def topics(self) -> list[str]:
        return list(self._topics.keys())

    async def publish(self, topic: str, event: Dict[str, Any]) -> None:
        q = await self._get_topic(topic)
        await q.put(event)

    async def subscribe(self, topic: str) -> AsyncIterator[Dict[str, Any]]:
        q = await self._get_topic(topic)
        while True:
            event = await q.get()
            yield event
            q.task_done()


_BUS: Any | None = None
_KNOWN_TOPICS: Set[str] = set()


def get_event_bus() -> Any:
    global _BUS
    if _BUS is None:
        if settings.KAFKA_ENABLED and settings.KAFKA_BOOTSTRAP_SERVERS:
            try:
                _BUS = KafkaEventBus()
            except KafkaUnavailableError:
                _BUS = InMemoryEventBus()
        else:
            _BUS = InMemoryEventBus()
    return _BUS


def tenant_topic(account_id: int, lane: str) -> str:
    return f"events.{lane}.{account_id}"


def track_topic(topic: str) -> None:
    _KNOWN_TOPICS.add(topic)


def known_topics() -> list[str]:
    return sorted(_KNOWN_TOPICS)
