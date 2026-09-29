
import re
import json
import jsonpath_ng

class ContextManager:
    """
    Manages variables extracted during a multi-step test run.
    """
    def __init__(self):
        self.store = {}

    def extract_from_response(self, response_data: dict, extraction_rules: list):
        """
        Extracts values from response body or headers based on YAML rules.
        """
        for rule in extraction_rules:
            # { "extract_body_param": { "key": "$.id", "as": "userId" } }
            if "extract_body_param" in rule:
                cfg = rule["extract_body_param"]
                try:
                    body_json = json.loads(response_data.get("body", "{}"))
                    jsonpath_expr = jsonpath_ng.parse(cfg["key"])
                    matches = jsonpath_expr.find(body_json)
                    if matches:
                        self.store[cfg["as"]] = matches[0].value
                except Exception:
                    pass
            
            # { "extract_header": { "key": "Set-Cookie", "as": "cookieValue" } }
            elif "extract_header" in rule:
                cfg = rule["extract_header"]
                header_val = response_data.get("headers", {}).get(cfg["key"])
                if header_val:
                    self.store[cfg["as"]] = header_val

    def substitute_variables(self, text: str) -> str:
        """
        Replaces ${var_name} with the value from the store.
        """
        if not isinstance(text, str):
            return text
            
        def replacer(match):
            var_name = match.group(1)
            return str(self.store.get(var_name, match.group(0)))
            
        return re.sub(r"\${(.*?)}", replacer, text)

    def substitute_recursive(self, data):
        """
        Recursively substitute variables in dicts or lists.
        """
        if isinstance(data, dict):
            return {
                self.substitute_variables(k) if isinstance(k, str) else k: self.substitute_recursive(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self.substitute_recursive(i) for i in data]
        elif isinstance(data, str):
            return self.substitute_variables(data)
        return data
