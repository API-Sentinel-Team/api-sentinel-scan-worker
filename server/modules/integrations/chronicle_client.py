"""Google Chronicle integration via webhook endpoint."""
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ChronicleClient:
    def __init__(self, endpoint_url: str, api_key: str | None = None):
        self.endpoint_url = endpoint_url
        self.api_key = api_key or ""

    async def send_event(self, event: Dict[str, Any]) -> bool:
        if not self.endpoint_url:
            return False
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.endpoint_url, json=event, headers=headers)
                return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.error("Chronicle send_event failed: %s", exc)
            return False
