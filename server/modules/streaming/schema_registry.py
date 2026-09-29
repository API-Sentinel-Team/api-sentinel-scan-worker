"""Simple schema registry with JSON Schema validation."""
from __future__ import annotations

from typing import Dict, Any
from jsonschema import Draft7Validator


class SchemaRegistry:
    def __init__(self) -> None:
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._validators: Dict[str, Draft7Validator] = {}

    def register(self, name: str, version: str, schema: Dict[str, Any]) -> None:
        key = f"{name}:{version}"
        self._schemas[key] = schema
        self._validators[key] = Draft7Validator(schema)

    def validate(self, name: str, version: str, payload: Dict[str, Any]) -> tuple[bool, str]:
        key = f"{name}:{version}"
        validator = self._validators.get(key)
        if not validator:
            return False, "schema_not_registered"
        errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
        if errors:
            return False, errors[0].message
        return True, ""


_REGISTRY: SchemaRegistry | None = None


def get_registry() -> SchemaRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = SchemaRegistry()
        _REGISTRY.register(
            "EnrichedEvent",
            "1.0",
            {
                "type": "object",
                "required": ["account_id", "endpoint_id", "actor_id", "response_code", "timestamp_ms"],
                "properties": {
                    "account_id": {"type": "integer"},
                    "endpoint_id": {"type": "string"},
                    "actor_id": {"type": "string"},
                    "response_code": {"type": "integer"},
                    "timestamp_ms": {"type": "integer"},
                    "path": {"type": "string"},
                    "method": {"type": "string"},
                    "latency_ms": {"type": ["integer", "null"]},
                    "quality_score": {"type": ["number", "null"]},
                },
            },
        )
    return _REGISTRY
