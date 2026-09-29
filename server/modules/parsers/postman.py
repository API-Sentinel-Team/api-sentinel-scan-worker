import json
import re
import uuid
import base64
from typing import Dict, Any, List, Optional, Tuple

class PostmanParser:
    def __init__(self, collection_json: str):
        self.data = json.loads(collection_json)
        self.variables = self._get_variable_map()
        self.auth_map = self._get_auth_map(self.data.get("auth", {}))

    def _get_variable_map(self) -> Dict[str, str]:
        """Extract variables from the collection root."""
        variables = {}
        for var in self.data.get("variable", []):
            if "key" in var and "value" in var:
                variables[var["key"]] = str(var["value"])
        return variables

    def _get_auth_map(self, auth_node: Dict[str, Any]) -> Dict[str, str]:
        """Maps Postman auth settings to HTTP headers."""
        if not auth_node:
            return {}
        
        auth_type = auth_node.get("type", "").lower()
        result = {}
        
        if auth_type == "bearer":
            # Extract bearer token
            token = ""
            for param in auth_node.get("bearer", []):
                if param.get("key") == "token":
                    token = self._replace_variables(param.get("value", ""))
            if token:
                result["Authorization"] = f"Bearer {token}"
                
        elif auth_type == "apikey":
            key_name = ""
            key_value = ""
            for param in auth_node.get("apikey", []):
                if param.get("key") == "key":
                    key_name = self._replace_variables(param.get("value", ""))
                elif param.get("key") == "value":
                    key_value = self._replace_variables(param.get("value", ""))
            if key_name and key_value:
                result[key_name] = key_value
                
        elif auth_type == "basic":
            user = ""
            pwd = ""
            for param in auth_node.get("basic", []):
                if param.get("key") == "username":
                    user = self._replace_variables(param.get("value", ""))
                elif param.get("key") == "password":
                    pwd = self._replace_variables(param.get("value", ""))
            if user or pwd:
                encoded = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                result["Authorization"] = f"Basic {encoded}"
                
        return result

    def _replace_variables(self, text: str) -> str:
        """Replace {{var}} with values from the variable map."""
        if not isinstance(text, str):
            return str(text)
            
        def replacer(match):
            var_name = match.group(1)
            return self.variables.get(var_name, match.group(0))
            
        return re.sub(r"\{\{(.*?)\}\}", replacer, text)

    def fetch_apis_recursively(self, items: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Traverse the item tree to find all requests."""
        if items is None:
            items = self.data.get("item", [])
            
        requests = []
        for item in items:
            if "item" in item:
                # Folder
                requests.extend(self.fetch_apis_recursively(item["item"]))
            elif "request" in item:
                # Request
                requests.append(item)
        return requests

    def convert_to_akto_format(self, item: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Converts a Postman item into our internal format.
        Returns (endpoint_metadata, sample_data)
        """
        request = item.get("request", {})
        
        # URL Logic
        url_node = request.get("url", {})
        if isinstance(url_node, str):
            raw_url = url_node
        else:
            raw_url = url_node.get("raw", "/")
        
        full_url = self._replace_variables(raw_url)
        
        # Headers Logic
        headers = self.auth_map.copy()
        if isinstance(request.get("header"), list):
            for h in request.get("header"):
                k = self._replace_variables(h.get("key", ""))
                v = self._replace_variables(h.get("value", ""))
                if k:
                    headers[k] = v
        
        # Body Logic
        body_node = request.get("body", {})
        request_body = ""
        mode = body_node.get("mode", "none")
        if mode == "raw":
            request_body = self._replace_variables(body_node.get("raw", ""))
        elif mode == "formdata":
            # Simplified form mapping
            kv = []
            for field in body_node.get("formdata", []):
                if field.get("type") == "text":
                    kv.append(f"{field.get('key')}={field.get('value')}")
            request_body = "&".join(kv)

        # Response Logic (Postman stores examples)
        responses = item.get("response", [])
        resp_data = {"status": 200, "headers": {}, "body": "{}"}
        if responses:
            first_resp = responses[0]
            resp_data["status"] = first_resp.get("code", 200)
            resp_data["body"] = first_resp.get("body", "{}")
            if isinstance(first_resp.get("header"), list):
                for h in first_resp.get("header"):
                    resp_data["headers"][h.get("key")] = h.get("value")

        endpoint = {
            "method": request.get("method", "GET"),
            "path": full_url,
            "api_type": "REST", # Postman is usually REST
            "last_seen": None
        }

        sample = {
            "request": {
                "method": endpoint["method"],
                "url": full_url,
                "headers": headers,
                "body": request_body
            },
            "response": resp_data
        }

        return endpoint, sample
