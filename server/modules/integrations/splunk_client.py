"""Splunk HEC (HTTP Event Collector) integration."""
import json
import time
import httpx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class SplunkClient:
    """Sends security events to Splunk via HTTP Event Collector (HEC)."""

    def __init__(self, hec_url: str, hec_token: str, index: str = "main", source: str = "api-security-engine"):
        self.hec_url = hec_url.rstrip("/") + "/services/collector/event"
        self.hec_token = hec_token
        self.index = index
        self.source = source

    async def send_event(self, event: Dict[str, Any], sourcetype: str = "api_security") -> bool:
        payload = {"time": time.time(), "host": "api-security-engine", "source": self.source,
                   "sourcetype": sourcetype, "index": self.index, "event": event}
        return await self._post([payload])

    async def send_vulnerability(self, vuln: Dict[str, Any]) -> bool:
        return await self.send_event({**vuln, "event_category": "vulnerability"}, sourcetype="api_vulnerability")

    async def send_threat(self, threat: Dict[str, Any]) -> bool:
        return await self.send_event({**threat, "event_category": "threat"}, sourcetype="api_threat")

    async def send_batch(self, events: List[Dict[str, Any]], sourcetype: str = "api_security") -> bool:
        payloads = [{"time": time.time(), "host": "api-security-engine", "source": self.source,
                     "sourcetype": sourcetype, "index": self.index, "event": e} for e in events]
        return await self._post(payloads)

    async def _post(self, payloads: List[Dict]) -> bool:
        body = "\n".join(json.dumps(p) for p in payloads)
        headers = {"Authorization": f"Splunk {self.hec_token}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
                resp = await client.post(self.hec_url, content=body, headers=headers)
                if resp.status_code == 200:
                    return True
                logger.error(f"Splunk HEC {resp.status_code}: {resp.text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Splunk send failed: {e}")
            return False
