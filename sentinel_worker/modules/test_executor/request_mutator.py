import copy
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class RequestMutator:
    """
    Mutates API requests based on Akto YAML 'execute' rules.
    Implements all 16 DSL mutation operations including modify_url.
    """

    AUTH_HEADERS = ["authorization", "x-api-key", "x-auth-token", "cookie", "token", "x-access-token"]

    def mutate(self, original_request: dict, rule: dict, auth_context: dict = None) -> dict:
        """
        Apply all mutation actions in a rule dict to a copy of the request.
        auth_context: {'attacker_token': 'Bearer xyz', 'auth_header': 'Authorization'}
        """
        mutated = copy.deepcopy(original_request)
        auth_context = auth_context or {}

        for action, params in rule.items():
            # ── URL mutation (most common: 90/208 templates) ──────────────────
            if action == "modify_url":
                mutated["url"] = self._modify_url(mutated.get("url", ""), params)

            # ── Body mutations ────────────────────────────────────────────────
            elif action == "modify_body_param":
                mutated["body"] = self._modify_body_param(mutated.get("body", "{}"), params)
            elif action == "add_body_param":
                mutated["body"] = self._add_body_param(mutated.get("body", "{}"), params)
            elif action == "delete_body_param":
                key = params if isinstance(params, str) else list(params.keys())[0]
                mutated["body"] = self._delete_body_param(mutated.get("body", "{}"), key)
            elif action == "replace_body":
                mutated["body"] = params if isinstance(params, str) else json.dumps(params)

            # ── Query param mutations ─────────────────────────────────────────
            elif action in ("modify_query_param", "add_query_param"):
                mutated["url"] = self._modify_query_param(mutated.get("url", ""), params)
            elif action == "delete_query_param":
                key = params if isinstance(params, str) else list(params.keys())[0]
                mutated["url"] = self._delete_query_param(mutated.get("url", ""), key)

            # ── Header mutations ──────────────────────────────────────────────
            elif action in ("add_header", "modify_header"):
                mutated.setdefault("headers", {})
                if isinstance(params, dict):
                    mutated["headers"] = self._apply_header_mutations(
                        mutated["headers"],
                        params,
                        auth_context,
                    )
            elif action == "delete_header":
                key = params if isinstance(params, str) else list(params.keys())[0]
                mutated["headers"] = {
                    k: v for k, v in mutated.get("headers", {}).items()
                    if k.lower() != key.lower()
                }

            # ── Auth mutations (core Akto operations) ─────────────────────────
            elif action == "remove_auth_header":
                if params:
                    mutated["headers"] = self._remove_auth_headers(mutated.get("headers", {}))
            elif action == "replace_auth_header":
                replacement_token = auth_context.get("attacker_token")
                if isinstance(params, str):
                    replacement_token = params
                if params and replacement_token:
                    mutated["headers"] = self._replace_auth_header(
                        mutated.get("headers", {}),
                        replacement_token,
                        auth_context.get("auth_header", "Authorization")
                    )

            # ── Method mutation ───────────────────────────────────────────────
            elif action == "modify_method":
                mutated["method"] = str(params).upper()

            # ── Redirect control ──────────────────────────────────────────────
            elif action == "follow_redirect":
                mutated["follow_redirect"] = bool(params)

        return mutated

    # ── URL helpers ────────────────────────────────────────────────────────────

    def _modify_url(self, url: str, new_path_or_url: str) -> str:
        """
        Replace or append URL path.
        - If new_path_or_url starts with http/https → full URL replacement.
        - If it starts with / → replace path component.
        - Otherwise → append to existing path (most common: ${urlVar}/apache.conf).
        """
        if not url:
            return new_path_or_url
        try:
            parsed = urlparse(url)
            target = str(new_path_or_url)
            if target.startswith("http://") or target.startswith("https://"):
                return target
            if target.startswith("/"):
                return urlunparse(parsed._replace(path=target, query=""))
            # Append: strip trailing slash from base path, prepend /
            base_path = parsed.path.rstrip("/")
            if not target.startswith("/"):
                target = "/" + target
            return urlunparse(parsed._replace(path=base_path + target, query=""))
        except Exception:
            return new_path_or_url

    def _modify_query_param(self, url: str, modifications: dict) -> str:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            flat = {k: v[0] for k, v in params.items()}
            flat.update({str(k): str(v) for k, v in modifications.items()})
            return urlunparse(parsed._replace(query=urlencode(flat)))
        except Exception:
            if "?" not in url:
                return url + "?" + "&".join([f"{k}={v}" for k, v in modifications.items()])
            return url

    def _delete_query_param(self, url: str, key: str) -> str:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop(key, None)
            flat = {k: v[0] for k, v in params.items()}
            return urlunparse(parsed._replace(query=urlencode(flat)))
        except Exception:
            return url

    # ── Body helpers ───────────────────────────────────────────────────────────

    def _modify_body_param(self, body: str, modifications: dict) -> str:
        try:
            data = json.loads(body) if body else {}
            for key, value in modifications.items():
                data[key] = value
            return json.dumps(data)
        except Exception:
            return body

    def _add_body_param(self, body: str, additions: dict) -> str:
        try:
            data = json.loads(body) if body else {}
            data.update(additions)
            return json.dumps(data)
        except Exception:
            return body

    def _delete_body_param(self, body: str, key: str) -> str:
        try:
            data = json.loads(body) if body else {}
            data.pop(key, None)
            return json.dumps(data)
        except Exception:
            return body

    # ── Auth helpers ───────────────────────────────────────────────────────────

    def _remove_auth_headers(self, headers: dict) -> dict:
        return {k: v for k, v in headers.items() if k.lower() not in self.AUTH_HEADERS}

    def _replace_auth_header(self, headers: dict, attacker_token: str, auth_header: str) -> dict:
        result = {k: v for k, v in headers.items() if k.lower() not in self.AUTH_HEADERS}
        result[auth_header] = attacker_token
        return result

    def _apply_header_mutations(self, headers: dict, params: dict, auth_context: dict) -> dict:
        result = dict(headers or {})
        auth_header = auth_context.get("auth_header", "Authorization")
        for key, value in params.items():
            key_text = str(key)
            value_text = str(value)
            if self._looks_like_auth_token(key_text) and value_text in {"1", "true", "True"}:
                result = self._replace_auth_header(result, key_text, auth_header)
                continue
            result[key_text] = value
        return result

    @staticmethod
    def _looks_like_auth_token(value: str) -> bool:
        normalized = str(value or "").strip().lower()
        return normalized.startswith(("bearer ", "basic "))
