"""Azure DevOps Boards integration — work item creation and management."""
import base64
import httpx
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AzureBoardsClient:
    """Creates and updates Azure DevOps Work Items (Bugs) via REST API v7."""

    def __init__(self, organization: str, project: str, personal_access_token: str):
        token_b64 = base64.b64encode(f":{personal_access_token}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token_b64}", "Content-Type": "application/json-patch+json"}
        self.base_url = f"https://dev.azure.com/{organization}/{project}/_apis"

    async def create_bug(self, title: str, description: str, severity: str = "MEDIUM",
                         tags: str = "api-security") -> Optional[str]:
        severity_map = {"CRITICAL": "1 - Critical", "HIGH": "2 - High", "MEDIUM": "3 - Medium", "LOW": "4 - Low"}
        payload = [
            {"op": "add", "path": "/fields/System.Title", "value": title},
            {"op": "add", "path": "/fields/System.Description", "value": description},
            {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Severity", "value": severity_map.get(severity.upper(), "3 - Medium")},
            {"op": "add", "path": "/fields/System.Tags", "value": tags},
        ]
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{self.base_url}/wit/workitems/$Bug?api-version=7.0",
                                         json=payload, headers=self.headers)
                resp.raise_for_status()
                return str(resp.json().get("id"))
        except Exception as e:
            logger.error(f"Azure Boards create_bug failed: {e}")
            return None

    async def update_state(self, item_id: str, state: str) -> bool:
        """state: Active | Resolved | Closed"""
        payload = [{"op": "add", "path": "/fields/System.State", "value": state}]
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.patch(f"{self.base_url}/wit/workitems/{item_id}?api-version=7.0",
                                          json=payload, headers=self.headers)
                return resp.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Azure Boards update_state failed: {e}")
            return False
