import base64
from mitmproxy import http
import datetime

class HARConverter:
    """
    Converts mitmproxy HTTPFlow objects into a subset of the HAR (HTTP Archive) format.
    """
    def flow_to_har_entry(self, flow: http.HTTPFlow) -> dict:
        request = flow.request
        response = flow.response

        # Request data
        req_data = {
            "method": request.method,
            "url": request.url,
            "httpVersion": request.http_version,
            "cookies": self._parse_cookies(request.cookies),
            "headers": [{"name": k, "value": v} for k, v in request.headers.items()],
            "queryString": [{"name": k, "value": v} for k, v in request.query.items()],
            "body": self._get_body_as_str(request.content) if request.content else "",
        }

        # Response data (if available)
        res_data = {}
        if response:
            res_data = {
                "status": response.status_code,
                "statusText": response.reason,
                "httpVersion": response.http_version,
                "cookies": self._parse_cookies(response.cookies),
                "headers": [{"name": k, "value": v} for k, v in response.headers.items()],
                "content": {
                    "size": len(response.content) if response.content else 0,
                    "mimeType": response.headers.get("Content-Type", ""),
                    "text": self._get_body_as_str(response.content) if response.content else ""
                }
            }

        return {
            "startedDateTime": datetime.datetime.fromtimestamp(flow.timestamp_start).isoformat(),
            "time": int((flow.timestamp_end - flow.timestamp_start) * 1000) if flow.timestamp_end else 0,
            "request": req_data,
            "response": res_data,
            "host": request.host,
            "port": request.port,
            "scheme": request.scheme
        }

    def _parse_cookies(self, cookies):
        return [{"name": name, "value": value} for name, value in cookies.items()]

    def _get_body_as_str(self, content: bytes) -> str:
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(content).decode("utf-8")
