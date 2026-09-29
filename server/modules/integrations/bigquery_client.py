"""Google BigQuery integration — export API security data for analytics."""
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class BigQueryClient:
    """Exports vulnerability, traffic, and endpoint data to Google BigQuery."""

    def __init__(self, project_id: str, dataset_id: str, credentials_json: Optional[Dict] = None):
        self.project_id = project_id
        self.dataset_id = dataset_id
        self._client = None
        try:
            from google.cloud import bigquery
            if credentials_json:
                from google.oauth2 import service_account
                creds = service_account.Credentials.from_service_account_info(credentials_json)
                self._client = bigquery.Client(project=project_id, credentials=creds)
            else:
                self._client = bigquery.Client(project=project_id)
        except ImportError:
            logger.warning("google-cloud-bigquery not installed. BigQuery integration disabled.")
        except Exception as e:
            logger.error(f"BigQuery init error: {e}")

    def is_available(self) -> bool:
        return self._client is not None

    def insert_rows(self, table_name: str, rows: List[Dict[str, Any]]) -> bool:
        if not self._client:
            logger.warning("BigQuery client not available")
            return False
        try:
            table_ref = f"{self.project_id}.{self.dataset_id}.{table_name}"
            errors = self._client.insert_rows_json(table_ref, rows)
            if errors:
                logger.error(f"BigQuery insert errors: {errors}")
                return False
            return True
        except Exception as e:
            logger.error(f"BigQuery insert_rows failed: {e}")
            return False

    def export_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> bool:
        rows = [{"id": v.get("id"), "account_id": v.get("account_id"), "type": v.get("type"),
                 "severity": v.get("severity"), "url": v.get("url"), "status": v.get("status"),
                 "created_at": str(v.get("created_at", ""))} for v in vulns]
        return self.insert_rows("vulnerabilities", rows)

    def export_endpoints(self, endpoints: List[Dict[str, Any]]) -> bool:
        rows = [{"id": e.get("id"), "account_id": e.get("account_id"), "method": e.get("method"),
                 "path": e.get("path"), "host": e.get("host"), "risk_score": e.get("risk_score", 0.0),
                 "last_seen": str(e.get("last_seen", ""))} for e in endpoints]
        return self.insert_rows("api_endpoints", rows)
