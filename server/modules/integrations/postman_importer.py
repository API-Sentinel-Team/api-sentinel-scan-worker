"""Postman Collection v2.0/v2.1 importer — converts to APIEndpoint dicts."""
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class PostmanImporter:
    """Parses Postman Collection JSON and extracts endpoint metadata."""

    @staticmethod
    def parse_collection(data: Dict[str, Any], account_id: int | None = None,
                         collection_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if account_id is None:
            raise ValueError("account_id is required")
        endpoints: List[Dict[str, Any]] = []
        PostmanImporter._walk(data.get("item", []), endpoints, account_id, collection_id)
        return endpoints

    @staticmethod
    def _walk(items: list, endpoints: list, account_id: int, collection_id: Optional[str]):
        for item in items:
            if "item" in item:
                PostmanImporter._walk(item["item"], endpoints, account_id, collection_id)
            elif "request" in item:
                req = item["request"]
                url_obj = req.get("url", {})
                if isinstance(url_obj, str):
                    raw = url_obj
                    protocol = raw.split(":")[0] if ":" in raw else "https"
                    host = raw.split("/")[2] if raw.startswith("http") else ""
                    path = "/" + "/".join(raw.split("/")[3:]) if "/" in raw else "/"
                else:
                    protocol = url_obj.get("protocol", "https")
                    host_parts = url_obj.get("host", [])
                    host = ".".join(host_parts) if isinstance(host_parts, list) else str(host_parts)
                    path_parts = url_obj.get("path", [])
                    path = "/" + "/".join(str(p).lstrip(":") for p in path_parts) if path_parts else "/"

                method = req.get("method", "GET").upper()
                headers = {h["key"]: h["value"] for h in req.get("header", []) if "key" in h}
                auth_types = []
                auth = req.get("auth", {})
                if auth:
                    auth_types.append(auth.get("type", "UNKNOWN").upper())
                auth_header = headers.get("Authorization", "")
                if "Bearer" in auth_header:
                    auth_types.append("JWT")
                elif "Basic" in auth_header:
                    auth_types.append("BASIC")

                body_raw = None
                body = req.get("body", {})
                if body and body.get("mode") == "raw":
                    body_raw = body.get("raw", "")

                endpoints.append({
                    "account_id": account_id, "collection_id": collection_id,
                    "method": method, "path": path, "path_pattern": path,
                    "host": host, "protocol": protocol,
                    "description": item.get("name", ""),
                    "auth_types_found": list(set(auth_types)),
                    "last_request_body": body_raw,
                    "api_type": "REST", "access_type": "PRIVATE",
                    "tags": {"source": "postman"},
                })

    @staticmethod
    def parse_from_file(path: str, account_id: int | None = None) -> List[Dict[str, Any]]:
        if account_id is None:
            raise ValueError("account_id is required")
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return PostmanImporter.parse_collection(data, account_id=account_id)
        except Exception as e:
            logger.error(f"Postman import error: {e}")
            return []
