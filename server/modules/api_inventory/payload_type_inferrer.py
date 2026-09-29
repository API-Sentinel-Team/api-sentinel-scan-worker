import json
import re
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class PayloadTypeInferrer:
    """
    Infers data types for response bodies (single-level or nested).
    Used to build a rich OpenAPI spec and detect data leaks.
    """
    def __init__(self):
        self.rules = [
            (r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', "UUID"),
            (r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', "EMAIL"),
            (r'^eyJ[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+$', "JWT"),
            (r'^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z?)?$', "DATE_TIME"),
            (r'^\d+$', "INTEGER"),
            (r'^(true|false)$', "BOOLEAN")
        ]

    def infer_schema(self, payload: Any, prefix: str = "") -> Dict[str, str]:
        """
        Recursively flattens keys and identifies their types.
        Returns a dict of {key_path: type_name}.
        """
        types = {}
        if isinstance(payload, dict):
            for k, v in payload.items():
                full_key = f"{prefix}.{k}" if prefix else k
                types.update(self.infer_schema(v, full_key))
        elif isinstance(payload, list):
            # Take the first item as a sample for the entire list type
            if payload:
                types.update(self.infer_schema(payload[0], f"{prefix}[]"))
            else:
                types[prefix] = "ARRAY<EMPTY>"
        else:
            # Primitive type
            inferred_type = type(payload).__name__
            for pattern, type_name in self.rules:
                if re.match(pattern, str(payload), re.IGNORECASE):
                    inferred_type = type_name
                    break
            types[prefix] = inferred_type
            
        return types
