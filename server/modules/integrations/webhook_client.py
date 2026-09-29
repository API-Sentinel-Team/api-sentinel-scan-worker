"""Generic outbound webhook client with HMAC-SHA256 signing and retry."""
import asyncio
import hashlib
import hmac
import httpx
import json
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class WebhookClient:
    """Sends signed JSON payloads to arbitrary webhook endpoints with retry logic."""

    def __init__(self, url: str, secret: str = "", method: str = "POST",
                 headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.secret = secret
        self.method = method.upper()
        self.extra_headers = headers or {}

    def _sign(self, body: bytes) -> str:
        return "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()

    async def send(self, payload: Dict[str, Any], event_type: str = "security_event") -> bool:
        body = json.dumps({**payload, "timestamp": int(time.time()), "event_type": event_type}).encode()
        headers = {"Content-Type": "application/json", "X-Security-Engine-Event": event_type, **self.extra_headers}
        if self.secret:
            headers["X-Webhook-Signature"] = self._sign(body)

        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.request(self.method, self.url, content=body, headers=headers)
                    if 200 <= resp.status_code < 300:
                        return True
                    logger.warning(f"Webhook attempt {attempt+1} failed: {resp.status_code}")
            except Exception as e:
                logger.warning(f"Webhook attempt {attempt+1} error: {e}")
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)

        return False
