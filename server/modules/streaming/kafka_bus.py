"""Kafka/Redpanda-backed event bus."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Dict, Optional, Set

try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
    from aiokafka.admin import AIOKafkaAdminClient, NewTopic
except Exception:  # pragma: no cover - optional dependency
    AIOKafkaProducer = None
    AIOKafkaConsumer = None
    AIOKafkaAdminClient = None
    NewTopic = None

from server.config import settings

logger = logging.getLogger(__name__)


class KafkaUnavailableError(RuntimeError):
    pass


class KafkaTopicManager:
    def __init__(self) -> None:
        if AIOKafkaAdminClient is None:
            raise KafkaUnavailableError("aiokafka is not installed")
        self._client: Optional[AIOKafkaAdminClient] = None

    async def _get_client(self) -> AIOKafkaAdminClient:
        if self._client is None:
            self._client = AIOKafkaAdminClient(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)
            await self._client.start()
        return self._client

    async def ensure_topic(self, topic: str) -> None:
        if not settings.KAFKA_AUTO_CREATE_TOPICS:
            return
        try:
            client = await self._get_client()
            topics = await client.list_topics()
            if topic in topics:
                return
            new_topic = NewTopic(
                name=topic,
                num_partitions=settings.KAFKA_TOPIC_PARTITIONS,
                replication_factor=settings.KAFKA_TOPIC_REPLICATION,
            )
            await client.create_topics([new_topic], validate_only=False)
        except Exception as exc:
            logger.warning("kafka_topic_create_failed", topic=topic, error=str(exc))

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None


class KafkaEventBus:
    def __init__(self) -> None:
        if AIOKafkaProducer is None or AIOKafkaConsumer is None:
            raise KafkaUnavailableError("aiokafka is not installed")
        self._producer: Optional[AIOKafkaProducer] = None
        self._topic_manager = KafkaTopicManager()
        self._known_topics: Set[str] = set()

    async def _get_producer(self) -> AIOKafkaProducer:
        if self._producer is None:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                client_id=settings.KAFKA_CLIENT_ID,
                security_protocol=settings.KAFKA_SECURITY_PROTOCOL or "PLAINTEXT",
                sasl_mechanism=settings.KAFKA_SASL_MECHANISM,
                sasl_plain_username=settings.KAFKA_SASL_USERNAME,
                sasl_plain_password=settings.KAFKA_SASL_PASSWORD,
                acks=settings.KAFKA_ACKS,
                linger_ms=settings.KAFKA_LINGER_MS,
            )
            await self._producer.start()
        return self._producer

    def topics(self) -> list[str]:
        return sorted(self._known_topics)

    async def publish(self, topic: str, event: Dict[str, Any]) -> None:
        await self._topic_manager.ensure_topic(topic)
        producer = await self._get_producer()
        payload = json.dumps(event, separators=(",", ":")).encode("utf-8")
        await producer.send_and_wait(topic, payload)
        self._known_topics.add(topic)

    async def subscribe(self, topic: str) -> AsyncIterator[Dict[str, Any]]:
        await self._topic_manager.ensure_topic(topic)
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            group_id=f"{settings.KAFKA_CONSUMER_GROUP_PREFIX}-{topic}",
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        await consumer.start()
        self._known_topics.add(topic)
        try:
            async for msg in consumer:
                try:
                    yield json.loads(msg.value.decode("utf-8"))
                except Exception:
                    continue
        finally:
            await consumer.stop()

    async def close(self) -> None:
        if self._producer:
            await self._producer.stop()
            self._producer = None
        await self._topic_manager.close()
