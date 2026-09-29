"""Microsoft Sentinel integration via HTTP Data Collector or Event Hub webhook."""
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SentinelClient:
    def __init__(self, endpoint_url: str, headers: Dict[str, str] | None = None):
        self.endpoint_url = endpoint_url
        self.headers = headers or {"Content-Type": "application/json"}

    async def send_event(self, event: Dict[str, Any]) -> bool:
        if not self.endpoint_url:
            return False
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.endpoint_url, json=event, headers=self.headers)
                return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.error("Sentinel send_event failed: %s", exc)
            return False
