"""Burp Suite XML export importer — converts proxy history to endpoints + sample data."""
import base64
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class BurpImporter:
    """Parses Burp Suite XML export and extracts HTTP request/response pairs."""

    @staticmethod
    def parse_xml(xml_content: str, account_id: int | None = None,
                  collection_id: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        if account_id is None:
            raise ValueError("account_id is required")
        endpoints: List[Dict[str, Any]] = []
        sample_data: List[Dict[str, Any]] = []
        seen: set = set()

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.error(f"Burp XML parse error: {e}")
            return {"endpoints": [], "sample_data": []}

        for item in root.findall("item"):
            try:
                url = (item.findtext("url") or "").strip()
                parsed = urlparse(url)
                method = (item.findtext("method") or "GET").upper()
                host = parsed.hostname or ""
                path = parsed.path or "/"
                protocol = parsed.scheme or "https"
                port = parsed.port

                req_body, req_headers = None, {}
                req_b64 = item.findtext("request")
                if req_b64:
                    try:
                        raw = base64.b64decode(req_b64).decode("utf-8", errors="replace")
                        parts = raw.split("\r\n\r\n", 1)
                        req_body = parts[1] if len(parts) > 1 else None
                        for line in parts[0].split("\r\n")[1:]:
                            if ":" in line:
                                k, v = line.split(":", 1)
                                req_headers[k.strip()] = v.strip()
                    except Exception:
                        pass

                resp_code, resp_body, resp_headers = 200, None, {}
                resp_b64 = item.findtext("response")
                if resp_b64:
                    try:
                        raw = base64.b64decode(resp_b64).decode("utf-8", errors="replace")
                        parts = raw.split("\r\n\r\n", 1)
                        status_line = parts[0].split("\r\n")[0]
                        tokens = status_line.split(" ")
                        resp_code = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 200
                        resp_body = parts[1][:5000] if len(parts) > 1 else None
                        for line in parts[0].split("\r\n")[1:]:
                            if ":" in line:
                                k, v = line.split(":", 1)
                                resp_headers[k.strip()] = v.strip()
                    except Exception:
                        pass

                auth_types = []
                auth_val = req_headers.get("Authorization", "")
                if "Bearer" in auth_val:
                    auth_types.append("JWT")
                elif "Basic" in auth_val:
                    auth_types.append("BASIC")

                key = f"{method}:{host}:{path}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "account_id": account_id, "collection_id": collection_id,
                        "method": method, "path": path, "path_pattern": path,
                        "host": host, "port": port, "protocol": protocol,
                        "auth_types_found": auth_types, "last_response_code": resp_code,
                        "last_request_body": req_body, "last_response_headers": resp_headers,
                        "api_type": "REST", "access_type": "PRIVATE",
                        "tags": {"source": "burp"},
                    })

                sample_data.append({
                    "account_id": account_id,
                    "request": {"method": method, "url": url, "headers": req_headers, "body": req_body},
                    "response": {"status_code": resp_code, "headers": resp_headers, "body": resp_body},
                })
            except Exception as e:
                logger.debug(f"Burp item error: {e}")

        return {"endpoints": endpoints, "sample_data": sample_data}
