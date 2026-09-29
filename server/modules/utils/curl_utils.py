import json
import shlex
from typing import Dict, Any, List

class CurlUtils:
    @classmethod
    def get_curl(cls, method: str, url: str, headers: Dict[str, str], payload: str = None) -> str:
        """Generate a cURL command from request parameters."""
        parts = ["curl", "-v"]
        
        # Method
        parts.extend(["-X", method.upper()])
        
        # Headers
        for k, v in headers.items():
            if k.lower() == "content-length":
                continue
            # Escaping for shell
            safe_header = f"{k}: {v}".replace("'", "'\\''")
            parts.extend(["-H", f"'{safe_header}'"])
            
        # Payload
        if payload and method.upper() not in ["GET", "HEAD"]:
            # Check if it's JSON for pretty display in command
            try:
                # Just verify it's JSON, don't reformat to avoid breaking raw payload
                json.loads(payload)
                # Escape single clips for shell
                safe_payload = payload.replace("'", "'\\''")
                parts.extend(["-d", f"'{safe_payload}'"])
            except:
                safe_payload = payload.replace("'", "'\\''")
                parts.extend(["-d", f"'{safe_payload}'"])
                
        # URL
        parts.append(f"'{url}'")
        
        return " ".join(parts)

    @classmethod
    def from_sample(cls, sample: Dict[str, Any]) -> str:
        """Generate cURL from a sample data dictionary (containing request/response)."""
        req = sample.get("request", {})
        method = req.get("method", "GET")
        url = req.get("url", "/")
        headers = req.get("headers", {})
        payload = req.get("body", "")
        
        return cls.get_curl(method, url, headers, payload)
