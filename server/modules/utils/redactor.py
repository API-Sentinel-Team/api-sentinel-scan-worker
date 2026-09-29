import json
import re
from typing import Any, Dict, List, Union
from urllib.parse import SplitResult, urlsplit, urlunsplit

class Redactor:
    REDACT_VALUE = "****"
    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "api-key",
        "apikey",
        "private-token",
        "x-github-token",
        "x-gitlab-token",
        "x-amz-security-token",
        "token",
    }
    URL_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")
    PATH_QUERY_RE = re.compile(r"(?<![:/])/[A-Za-z0-9._~!$&'()*+,;=:@%/{}-]+\?[^\s\"'<>]+")
    SENSITIVE_TEXT_RE = re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|cookie)\b\s*[:=]\s*['\"]?[^'\"\s,&;]+"
    )
    AUTH_VALUE_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
    
    @classmethod
    def redact_json(cls, data: Union[Dict, List, str], level: int = 0) -> Union[Dict, List, str]:
        """Recursively redact sensitive fields in a JSON object or list."""
        if isinstance(data, str):
            try:
                # If it's a string, try to parse it as JSON
                parsed = json.loads(data)
                redacted = cls.redact_json(parsed, level + 1)
                return json.dumps(redacted)
            except:
                return cls.redact_text(data)

        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                # Check for sensitive keys
                if any(s in k.lower() for s in ["password", "secret", "token", "key", "auth", "cvv", "credit_card"]):
                    new_dict[k] = cls.REDACT_VALUE
                else:
                    new_dict[k] = cls.redact_json(v, level + 1)
            return new_dict

        if isinstance(data, list):
            return [cls.redact_json(item, level + 1) for item in data]

        return data

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Redact common inline secret patterns in non-JSON text."""
        if not isinstance(text, str):
            return text
        text = cls.AUTH_VALUE_RE.sub(lambda match: f"{match.group(1)} {cls.REDACT_VALUE}", text)
        text = cls.SENSITIVE_TEXT_RE.sub(lambda match: f"{match.group(1)}={cls.REDACT_VALUE}", text)
        if text.lstrip().lower().startswith(("http://", "https://")):
            leading = text[: len(text) - len(text.lstrip())]
            return leading + cls._redact_url_match(text.lstrip())
        text = cls.URL_RE.sub(lambda match: cls._redact_url_match(match.group(0)), text)
        return cls.PATH_QUERY_RE.sub(lambda match: cls._redact_url_match(match.group(0)), text)

    @classmethod
    def _redact_url_match(cls, value: str) -> str:
        trailing = ""
        while value and value[-1] in ".,);]}":
            trailing = value[-1] + trailing
            value = value[:-1]
        return cls.redact_url(value) + trailing

    @classmethod
    def redact_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive HTTP headers."""
        new_headers = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if cls._is_sensitive_header(k_lower):
                if k_lower == "authorization":
                    # Keep the scheme (Bearer, Basic) but mask the token
                    parts = v.split(" ", 1)
                    if len(parts) > 1:
                        new_headers[k] = f"{parts[0]} {cls.REDACT_VALUE}"
                    else:
                        new_headers[k] = cls.REDACT_VALUE
                elif k_lower == "cookie":
                    # Redact value of each cookie
                    cookies = v.split(";")
                    redacted_cookies = []
                    for c in cookies:
                        if "=" in c:
                            name, _ = c.split("=", 1)
                            redacted_cookies.append(f"{name.strip()}={cls.REDACT_VALUE}")
                        else:
                            redacted_cookies.append(cls.REDACT_VALUE)
                    new_headers[k] = "; ".join(redacted_cookies)
                else:
                    new_headers[k] = cls.REDACT_VALUE
            else:
                new_headers[k] = v
        return new_headers

    @classmethod
    def _is_sensitive_header(cls, key_lower: str) -> bool:
        normalized = key_lower.replace("_", "-")
        if normalized in cls.SENSITIVE_HEADERS:
            return True
        return normalized.endswith(("-token", "-api-key", "-secret", "-password", "-private-key"))

    @classmethod
    def redact_url(cls, url: str) -> str:
        """Redact credentials and query parameters in a URL."""
        safe_url = cls._redact_url_userinfo(str(url))
        if "?" not in safe_url:
            return safe_url

        base, query = safe_url.split("?", 1)
        params = query.split("&")
        redacted_params = []
        for p in params:
            if "=" in p:
                name, _ = p.split("=", 1)
                redacted_params.append(f"{name}={cls.REDACT_VALUE}")
            else:
                redacted_params.append(p)

        return f"{base}?{'&'.join(redacted_params)}"

    @classmethod
    def _redact_url_userinfo(cls, url: str) -> str:
        try:
            parsed = urlsplit(url)
        except ValueError:
            return url
        if not parsed.netloc or "@" not in parsed.netloc:
            return url

        host_port = parsed.netloc.rsplit("@", 1)[1]
        redacted = SplitResult(
            parsed.scheme,
            f"{cls.REDACT_VALUE}@{host_port}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
        return urlunsplit(redacted)

    @classmethod
    def redact_http_message(cls, message: Dict[str, Any] | None) -> Dict[str, Any] | None:
        """Redact a stored HTTP request/response evidence object."""
        if message is None:
            return None
        redacted = dict(message)
        if redacted.get("url"):
            redacted["url"] = cls.redact_url(str(redacted["url"]))
        if isinstance(redacted.get("headers"), dict):
            redacted["headers"] = cls.redact_headers(redacted["headers"])
        if "body" in redacted:
            redacted["body"] = cls.redact_json(redacted["body"])
        return redacted

    @classmethod
    def redact_scan_result(cls, result: Dict[str, Any]) -> Dict[str, Any]:
        """Redact scanner result evidence before persistence or API exposure."""
        redacted = cls._redact_scan_value(dict(result))
        redacted["sent_request"] = cls.redact_http_message(redacted.get("sent_request"))
        redacted["received_response"] = cls.redact_http_message(redacted.get("received_response"))
        if isinstance(redacted.get("results"), list):
            safe_results = []
            for item in redacted["results"]:
                safe_item = cls._redact_scan_value(item)
                if isinstance(safe_item, dict):
                    response = safe_item.get("response")
                    if isinstance(response, dict) and isinstance(response.get("headers"), dict):
                        response["headers"] = cls.redact_headers(response["headers"])
                safe_results.append(safe_item)
            redacted["results"] = safe_results
        return redacted

    @classmethod
    def _redact_scan_value(cls, value: Any, key: str | None = None) -> Any:
        key_lower = (key or "").lower()
        if isinstance(value, dict):
            if key_lower.endswith("headers"):
                return cls.redact_headers(value)
            return {item_key: cls._redact_scan_value(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [cls._redact_scan_value(item, key) for item in value]
        if isinstance(value, str):
            if cls._is_sensitive_scan_key(key_lower):
                return cls.REDACT_VALUE
            if key_lower == "body":
                return cls.redact_json(value)
            if key_lower in {"url", "base_url", "evidence_url"}:
                return cls.redact_url(value)
            return cls.redact_text(value)
        return value

    @classmethod
    def _is_sensitive_scan_key(cls, key_lower: str) -> bool:
        if not key_lower:
            return False
        normalized = key_lower.replace("-", "_")
        sensitive_names = {
            "authorization",
            "cookie",
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "client_secret",
            "private_key",
            "secret_key",
            "proof",
        }
        if normalized in sensitive_names:
            return True
        return normalized.endswith(("_token", "_secret", "_password", "_api_key", "_private_key"))
