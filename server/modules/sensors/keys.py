from __future__ import annotations

import hashlib
import hmac
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import Sensor

SENSOR_KEY_HASH_PREFIX = "hmac-sha256:"


def generate_sensor_key() -> str:
    return secrets.token_hex(32)


def _hash_secret() -> str:
    return settings.SENSOR_KEY_HASH_PEPPER or settings.ENCRYPTION_KEY or settings.JWT_SECRET


def hash_sensor_key(raw_key: str) -> str:
    digest = hmac.new(
        _hash_secret().encode("utf-8"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{SENSOR_KEY_HASH_PREFIX}{digest}"


def sensor_key_is_hashed(value: str | None) -> bool:
    return bool(value and value.startswith(SENSOR_KEY_HASH_PREFIX))


async def resolve_sensor_by_key(db: AsyncSession, raw_key: str | None) -> Sensor | None:
    if not raw_key:
        return None

    hashed_key = hash_sensor_key(raw_key)
    result = await db.execute(select(Sensor).where(Sensor.sensor_key == hashed_key))
    sensor = result.scalar_one_or_none()
    if sensor:
        return sensor

    legacy = await db.execute(select(Sensor).where(Sensor.sensor_key == raw_key))
    sensor = legacy.scalar_one_or_none()
    if sensor and not sensor_key_is_hashed(sensor.sensor_key):
        return sensor
    return None
