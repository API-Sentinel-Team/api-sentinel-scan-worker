"""PagerDuty Events API v2 integration."""
import httpx
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyClient:
    """Sends incidents/alerts to PagerDuty via Events API v2."""

    def __init__(self, routing_key: str):
        self.routing_key = routing_key

    async def trigger(self, summary: str, severity: str = "warning", source: str = "api-security-engine",
                      custom_details: Optional[Dict[str, Any]] = None, dedup_key: Optional[str] = None) -> Optional[str]:
        payload: Dict[str, Any] = {
            "routing_key": self.routing_key, "event_action": "trigger",
            "payload": {"summary": summary, "severity": severity, "source": source,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "custom_details": custom_details or {}},
        }
        if dedup_key:
            payload["dedup_key"] = dedup_key
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(PAGERDUTY_EVENTS_URL, json=payload)
                if resp.status_code in (200, 202):
                    return resp.json().get("dedup_key", dedup_key or "unknown")
                logger.error(f"PagerDuty trigger failed: {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"PagerDuty trigger error: {e}")
            return None

    async def acknowledge(self, dedup_key: str) -> bool:
        return await self._action("acknowledge", dedup_key)

    async def resolve(self, dedup_key: str) -> bool:
        return await self._action("resolve", dedup_key)

    async def _action(self, action: str, dedup_key: str) -> bool:
        payload = {"routing_key": self.routing_key, "event_action": action, "dedup_key": dedup_key}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(PAGERDUTY_EVENTS_URL, json=payload)
                return resp.status_code in (200, 202)
        except Exception as e:
            logger.error(f"PagerDuty {action} error: {e}")
            return False

    async def trigger_vulnerability(self, vuln: Dict[str, Any]) -> Optional[str]:
        sev_map = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info"}
        return await self.trigger(
            summary=f"API Vuln [{vuln.get('severity','MEDIUM')}]: {vuln.get('type','Unknown')} at {vuln.get('url','N/A')}",
            severity=sev_map.get(vuln.get("severity", "MEDIUM"), "warning"),
            custom_details={k: v for k, v in vuln.items() if k in ("type","severity","url","description","endpoint_id")},
            dedup_key=f"vuln-{vuln.get('id','unknown')}",
        )
