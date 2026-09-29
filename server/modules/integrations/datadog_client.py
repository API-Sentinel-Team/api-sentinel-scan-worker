"""Datadog integration — metrics, events, and security signals."""
import time
import httpx
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class DatadogClient:
    """Sends metrics and security events to Datadog via API v1."""

    def __init__(self, api_key: str, app_key: str = "", site: str = "datadoghq.com"):
        self.base_url = f"https://api.{site}/api/v1"
        self.headers = {"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key, "Content-Type": "application/json"}

    async def send_event(self, title: str, text: str, alert_type: str = "warning",
                         tags: Optional[List[str]] = None) -> bool:
        payload = {"title": title, "text": text, "alert_type": alert_type,
                   "tags": tags or ["source:api-security-engine"], "date_happened": int(time.time())}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(f"{self.base_url}/events", json=payload, headers=self.headers)
                return resp.status_code in (200, 202)
        except Exception as e:
            logger.error(f"Datadog event failed: {e}")
            return False

    async def send_metric(self, metric_name: str, value: float, tags: Optional[List[str]] = None,
                          metric_type: str = "gauge") -> bool:
        payload = {"series": [{"metric": metric_name, "points": [[int(time.time()), value]],
                                "type": metric_type, "tags": tags or ["source:api-security-engine"],
                                "host": "api-security-engine"}]}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(f"{self.base_url}/series", json=payload, headers=self.headers)
                return resp.status_code in (200, 202)
        except Exception as e:
            logger.error(f"Datadog metric failed: {e}")
            return False

    async def send_vulnerability_event(self, vuln: Dict[str, Any]) -> bool:
        severity = vuln.get("severity", "MEDIUM")
        alert_map = {"CRITICAL": "error", "HIGH": "warning", "MEDIUM": "warning", "LOW": "info"}
        return await self.send_event(
            title=f"API Vulnerability: {vuln.get('type', 'Unknown')} [{severity}]",
            text=f"Endpoint: {vuln.get('url', 'N/A')}\n{vuln.get('description', '')}",
            alert_type=alert_map.get(severity, "warning"),
            tags=[f"severity:{severity.lower()}", "source:api-security-engine"],
        )

    async def flush_metrics(self, open_vulns: int, critical_vulns: int, endpoints_scanned: int) -> bool:
        ok = True
        ok &= await self.send_metric("api_security.vulnerabilities.open", open_vulns)
        ok &= await self.send_metric("api_security.vulnerabilities.critical", critical_vulns)
        ok &= await self.send_metric("api_security.endpoints.scanned", endpoints_scanned, metric_type="count")
        return ok
