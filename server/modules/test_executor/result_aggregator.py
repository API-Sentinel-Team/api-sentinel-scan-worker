from server.modules.persistence.database import AsyncSessionLocal
from server.api.websocket.manager import ws_manager
from server.api.websocket.event_types import WSEventType
from server.modules.test_executor.evidence import build_active_scan_evidence
from server.modules.vulnerability_detector.lifecycle import vulnerability_confidence_from_evidence
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability


class ResultAggregator:
    """
    Saves test results as persistent vulnerabilities in the database.
    """
    def __init__(self, db=None):
        self.db = db

    @staticmethod
    def _account_id_for(endpoint: dict, test_result: dict) -> int:
        account_id = endpoint.get("account_id", test_result.get("account_id"))
        if account_id is None:
            raise ValueError("ResultAggregator requires account_id on the endpoint or test result")
        return int(account_id)

    async def add_vulnerability(self, test_result: dict, endpoint: dict):
        """
        Processes a raw ExecutionEngine result and stores it if vulnerable.
        """
        if not test_result.get("is_vulnerable"):
            return

        account_id = self._account_id_for(endpoint, test_result)
        evidence = build_active_scan_evidence(test_result, endpoint)

        if self.db is not None:
            db = self.db
            vuln, created, fingerprint = await create_or_merge_vulnerability(
                db,
                {
                    "account_id": account_id,
                    "template_id": test_result["template_id"],
                    "endpoint_id": endpoint.get("id"),
                    "url": endpoint.get("url") or endpoint.get("path"),
                    "method": endpoint.get("method"),
                    "severity": test_result.get("severity", "MEDIUM"),
                    "type": test_result.get("type") or test_result["template_id"],
                    "status": "OPEN",
                    "confidence": vulnerability_confidence_from_evidence(evidence),
                    "remediation": evidence.get("remediation"),
                    "evidence": evidence,
                },
            )
        else:
            async with AsyncSessionLocal() as db:
                vuln, created, fingerprint = await create_or_merge_vulnerability(
                    db,
                    {
                        "account_id": account_id,
                        "template_id": test_result["template_id"],
                        "endpoint_id": endpoint.get("id"),
                        "url": endpoint.get("url") or endpoint.get("path"),
                        "method": endpoint.get("method"),
                        "severity": test_result.get("severity", "MEDIUM"),
                        "type": test_result.get("type") or test_result["template_id"],
                        "status": "OPEN",
                        "confidence": vulnerability_confidence_from_evidence(evidence),
                        "remediation": evidence.get("remediation"),
                        "evidence": evidence,
                    },
                )
                await db.commit()

        if not created:
            return

        # Broadcast to all connected Dashboard clients
        await ws_manager.broadcast({
            "type": WSEventType.VULNERABILITY_FOUND,
            "data": {
                "id": vuln.id,
                "template_id": vuln.template_id,
                "severity": vuln.severity,
                "url": vuln.url,
                "method": vuln.method,
                "fingerprint": fingerprint,
                "timestamp": vuln.created_at.isoformat() if vuln.created_at else None
            }
        })
        
        print(f"Recorded vulnerability: {test_result['template_id']} on {endpoint['path']}")
