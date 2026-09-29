import re
import json
from difflib import SequenceMatcher


class ResponseValidator:
    """
    Validates API responses against Akto YAML 'validate' rules.
    Implements all assertion types including contains_all, contains_either,
    not_contains_either, percentage_match, percentage_match_schema, and OR logic.
    """

    def validate(self, response: dict, rules: dict, original_response: dict = None) -> bool:
        # 1. Response code
        if "response_code" in rules:
            if not self._check_code(rules["response_code"], response.get("status_code", 0)):
                return False

        # 2. Response payload
        if "response_payload" in rules:
            body = response.get("body", "")
            original_body = (original_response or {}).get("body", "")
            if not self._check_payload(rules["response_payload"], body, original_body):
                return False

        # 3. Response header checks
        if "response_header" in rules:
            if not self._check_headers(rules["response_header"], response.get("headers", {})):
                return False

        return True

    # ── Code ──────────────────────────────────────────────────────────────────

    def _check_code(self, rule: dict, code: int) -> bool:
        if "gte" in rule and code < rule["gte"]:
            return False
        if "lt" in rule and code >= rule["lt"]:
            return False
        if "eq" in rule and code != rule["eq"]:
            return False
        if "neq" in rule and code == rule["neq"]:
            return False
        return True

    # ── Payload ───────────────────────────────────────────────────────────────

    def _check_payload(self, rules: dict, body: str, original_body: str = "") -> bool:
        body_lower = body.lower()

        # OR logic — if any sub-condition passes, the whole payload check passes
        if "or" in rules:
            return any(self._check_payload(sub, body, original_body) for sub in rules["or"])

        # Length
        if "length" in rules:
            if not self._check_numeric(rules["length"], len(body)):
                return False

        # contains — every item must be present
        for item in rules.get("contains", []):
            if item.lower() not in body_lower:
                return False

        # contains_all — alias for contains (every item must be present)
        items_all = rules.get("contains_all", [])
        if isinstance(items_all, str):
            items_all = [items_all]
        for item in items_all:
            if item.lower() not in body_lower:
                return False

        # contains_either — at least one item must be present
        items_either = rules.get("contains_either", [])
        if isinstance(items_either, str):
            items_either = [items_either]
        if items_either and not any(item.lower() in body_lower for item in items_either):
            return False

        # not_contains — none of the items should be present
        for item in rules.get("not_contains", []):
            if item.lower() in body_lower:
                return False

        # not_contains_either — same as not_contains (any match → fail)
        items_nc_either = rules.get("not_contains_either", [])
        if isinstance(items_nc_either, str):
            items_nc_either = [items_nc_either]
        for item in items_nc_either:
            if item.lower() in body_lower:
                return False

        # regex
        regex_pattern = rules.get("regex")
        if regex_pattern:
            if not re.search(regex_pattern, body, re.IGNORECASE):
                return False

        # percentage_match — similarity vs original response
        pm_rule = rules.get("percentage_match")
        if pm_rule and original_body is not None:
            pct = self._percentage_match(original_body, body)
            if not self._check_numeric(pm_rule, pct):
                return False

        # percentage_match_schema — JSON schema (keys) similarity
        pms_rule = rules.get("percentage_match_schema")
        if pms_rule and original_body is not None:
            pct = self._percentage_match_schema(original_body, body)
            if not self._check_numeric(pms_rule, pct):
                return False

        # for_one — at least one JSON field satisfies condition
        if "for_one" in rules:
            if not self._check_for_one(rules["for_one"], body):
                return False

        return True

    def _check_for_one(self, rule: dict, body: str) -> bool:
        """Check that at least one key/value in JSON body satisfies the rule."""
        key_rule = rule.get("key", {})
        value_rule = rule.get("value", {})
        try:
            data = json.loads(body) if body else {}
        except Exception:
            return False
        return self._scan_for_one(data, key_rule, value_rule)

    def _scan_for_one(self, obj, key_rule: dict, value_rule: dict) -> bool:
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                k_ok = True
                if "eq" in key_rule and k_str != key_rule["eq"]:
                    k_ok = False
                if "not_contains" in key_rule:
                    nc = key_rule["not_contains"]
                    nc_list = nc if isinstance(nc, list) else [nc]
                    if any(x.lower() in k_str.lower() for x in nc_list):
                        k_ok = False
                if "regex" in key_rule and not re.search(key_rule["regex"], k_str):
                    k_ok = False

                if k_ok and value_rule:
                    v_str = str(v)
                    v_ok = True
                    if "datatype" in value_rule:
                        if value_rule["datatype"] == "number" and not isinstance(v, (int, float)):
                            v_ok = False
                        elif value_rule["datatype"] == "string" and not isinstance(v, str):
                            v_ok = False
                    if v_ok:
                        return True

                if self._scan_for_one(v, key_rule, value_rule):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._scan_for_one(item, key_rule, value_rule):
                    return True
        return False

    # ── Headers ───────────────────────────────────────────────────────────────

    def _check_headers(self, rule: dict, headers: dict) -> bool:
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for_one = rule.get("for_one", {})
        if for_one:
            key_rule = for_one.get("key", {})
            value_rule = for_one.get("value", {})
            for k, v in lower_headers.items():
                k_match = True
                if "eq" in key_rule and k != key_rule["eq"].lower():
                    k_match = False
                if "regex" in key_rule and not re.search(key_rule["regex"], k, re.IGNORECASE):
                    k_match = False
                if not k_match:
                    continue
                if "contains" in value_rule and value_rule["contains"].lower() in v.lower():
                    return True
                if "regex" in value_rule and re.search(value_rule["regex"], v):
                    return True
                if not value_rule:
                    return True
            return False

        contains = rule.get("contains", {})
        for k, v in contains.items():
            if k.lower() not in lower_headers:
                return False
            if v and v.lower() not in lower_headers[k.lower()].lower():
                return False

        return True

    # ── Similarity ─────────────────────────────────────────────────────────────

    def _percentage_match(self, original: str, mutated: str) -> float:
        if not original and not mutated:
            return 100.0
        if not original or not mutated:
            return 0.0
        ratio = SequenceMatcher(None, original, mutated).ratio()
        return round(ratio * 100, 2)

    def _percentage_match_schema(self, original_body: str, mutated_body: str) -> float:
        try:
            orig = json.loads(original_body)
            mut = json.loads(mutated_body)
            orig_keys = set(self._flatten_keys(orig))
            mut_keys = set(self._flatten_keys(mut))
            if not orig_keys:
                return 0.0
            overlap = len(orig_keys & mut_keys)
            return round((overlap / len(orig_keys)) * 100, 2)
        except Exception:
            return self._percentage_match(original_body, mutated_body)

    def _flatten_keys(self, obj, prefix="") -> list:
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                keys.extend(self._flatten_keys(v, full_key))
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:3]):
                keys.extend(self._flatten_keys(item, f"{prefix}[{i}]"))
        return keys

    # ── Numeric helper ─────────────────────────────────────────────────────────

    def _check_numeric(self, rule: dict, value: float) -> bool:
        if "gt" in rule and value <= rule["gt"]:
            return False
        if "gte" in rule and value < rule["gte"]:
            return False
        if "lt" in rule and value >= rule["lt"]:
            return False
        if "lte" in rule and value > rule["lte"]:
            return False
        if "eq" in rule and value != rule["eq"]:
            return False
        return True
