"""Minimal ClickHouse HTTP client for warm store exports."""
from __future__ import annotations

import httpx
import logging
from typing import Iterable, Dict, Any

from server.config import settings

logger = logging.getLogger(__name__)


class ClickHouseClient:
    def __init__(self) -> None:
        self.base_url = settings.CLICKHOUSE_URL.rstrip("/")
        self.user = settings.CLICKHOUSE_USER
        self.password = settings.CLICKHOUSE_PASSWORD
        self.database = settings.CLICKHOUSE_DATABASE
        self.timeout = settings.CLICKHOUSE_TIMEOUT_SECONDS

    def _auth(self) -> tuple[str, str] | None:
        if self.user:
            return (self.user, self.password or "")
        return None

    async def execute(self, query: str) -> bool:
        url = f"{self.base_url}/"
        params = {"query": query}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, params=params, auth=self._auth())
                return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.error("clickhouse_execute_error", error=str(exc))
            return False

    async def insert_json_each_row(self, table: str, rows: Iterable[Dict[str, Any]]) -> bool:
        url = f"{self.base_url}/"
        query = f"INSERT INTO {self.database}.{table} FORMAT JSONEachRow"
        import json
        payload = "\n".join([json.dumps(row) for row in rows])
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    url,
                    params={"query": query},
                    auth=self._auth(),
                    content=payload.encode("utf-8"),
                )
                return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.error("clickhouse_insert_error", error=str(exc))
            return False

    async def ensure_tables(self) -> None:
        await self.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        await self.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.database}.endpoint_metrics_hourly (
                account_id UInt64,
                endpoint_id String,
                hour_ts UInt64,
                request_count UInt64,
                error_count UInt64,
                avg_latency_ms Float64,
                p95_latency_ms Float64
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(toDateTime(hour_ts))
            ORDER BY (account_id, endpoint_id, hour_ts)
            """
        )
        await self.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.database}.actor_metrics_hourly (
                account_id UInt64,
                actor_id String,
                hour_ts UInt64,
                request_count UInt64,
                error_count UInt64,
                avg_latency_ms Float64
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(toDateTime(hour_ts))
            ORDER BY (account_id, actor_id, hour_ts)
            """
        )
        await self.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.database}.alert_metrics_daily (
                account_id UInt64,
                day String,
                total UInt64,
                critical UInt64,
                high UInt64,
                medium UInt64,
                low UInt64
            ) ENGINE = MergeTree()
            ORDER BY (account_id, day)
            """
        )
