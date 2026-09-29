"""OpenAPI spec diffing focused on client-breaking changes.

Inspired by tools like oasdiff/open-api-diff, but intentionally lightweight
for the project's built-in governance and posture workflows.
"""
from __future__ import annotations

from hashlib import sha256
from typing import Any


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


class OpenAPIDiffAnalyzer:
    """Compare two OpenAPI specs and report backward-breaking changes."""

    def compare(self, base_spec: dict[str, Any] | None, revision_spec: dict[str, Any] | None) -> dict[str, Any]:
        base = base_spec or {}
        revision = revision_spec or {}
        changes: list[dict[str, Any]] = []

        base_paths = base.get("paths") or {}
        revision_paths = revision.get("paths") or {}

        for path, base_path_item in base_paths.items():
            if not isinstance(base_path_item, dict):
                continue

            revision_path_item = revision_paths.get(path)
            if not isinstance(revision_path_item, dict):
                methods = sorted(m.upper() for m in base_path_item.keys() if m.lower() in HTTP_METHODS)
                changes.append(
                    self._build_change(
                        change_id="path_removed",
                        severity="HIGH",
                        path=path,
                        method=None,
                        component="endpoint",
                        message=f"Path {path} was removed from the revised spec",
                        why_it_matters="Clients calling this path will receive errors after rollout.",
                        recommended_action="Keep the path available, or introduce a new version before removing it.",
                        details={"methods": methods},
                    )
                )
                continue

            changes.extend(self._compare_path(base, revision, path, base_path_item, revision_path_item))

        return {
            "summary": self._build_summary(changes),
            "breaking_changes": sorted(changes, key=lambda item: (item["path"], item["method"] or "", item["id"])),
            "recommendations": self._build_recommendations(changes),
        }

    def _compare_path(
        self,
        base_spec: dict[str, Any],
        revision_spec: dict[str, Any],
        path: str,
        base_path_item: dict[str, Any],
        revision_path_item: dict[str, Any],
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for method, base_operation in base_path_item.items():
            method_lc = method.lower()
            if method_lc not in HTTP_METHODS or not isinstance(base_operation, dict):
                continue

            revision_operation = revision_path_item.get(method_lc)
            if not isinstance(revision_operation, dict):
                changes.append(
                    self._build_change(
                        change_id="method_removed",
                        severity="HIGH",
                        path=path,
                        method=method_lc.upper(),
                        component="endpoint",
                        message=f"{method_lc.upper()} {path} was removed from the revised spec",
                        why_it_matters="Existing clients for this operation will fail after deployment.",
                        recommended_action="Keep the operation available, or ship a versioned replacement first.",
                    )
                )
                continue

            changes.extend(
                self._compare_operation(
                    base_spec=base_spec,
                    revision_spec=revision_spec,
                    path=path,
                    method=method_lc.upper(),
                    base_path_item=base_path_item,
                    revision_path_item=revision_path_item,
                    base_operation=base_operation,
                    revision_operation=revision_operation,
                )
            )
        return changes

    def _compare_operation(
        self,
        *,
        base_spec: dict[str, Any],
        revision_spec: dict[str, Any],
        path: str,
        method: str,
        base_path_item: dict[str, Any],
        revision_path_item: dict[str, Any],
        base_operation: dict[str, Any],
        revision_operation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []

        changes.extend(self._compare_security(base_spec, revision_spec, path, method, base_operation, revision_operation))
        changes.extend(self._compare_parameters(path, method, base_path_item, revision_path_item, base_operation, revision_operation))
        changes.extend(self._compare_request_body(path, method, base_operation, revision_operation))
        changes.extend(self._compare_responses(path, method, base_operation, revision_operation))

        return changes

    def _compare_security(
        self,
        base_spec: dict[str, Any],
        revision_spec: dict[str, Any],
        path: str,
        method: str,
        base_operation: dict[str, Any],
        revision_operation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        base_security = self._normalize_security(self._resolve_security(base_spec, base_operation))
        revision_security = self._normalize_security(self._resolve_security(revision_spec, revision_operation))

        if not base_security and revision_security:
            return [
                self._build_change(
                    change_id="security_requirement_added",
                    severity="HIGH",
                    path=path,
                    method=method,
                    component="security",
                    message=f"{method} {path} now requires authentication/authorization",
                    why_it_matters="Unauthenticated or differently-authenticated existing clients will start failing.",
                    recommended_action="Roll out the new security requirement behind versioning or a compatibility window.",
                    details={"security": revision_security},
                )
            ]

        if base_security and revision_security and base_security != revision_security:
            return [
                self._build_change(
                    change_id="security_requirement_changed",
                    severity="HIGH",
                    path=path,
                    method=method,
                    component="security",
                    message=f"{method} {path} changed its security requirements",
                    why_it_matters="Clients may need new credentials, scopes, or token types to keep working.",
                    recommended_action="Document the auth migration explicitly and version the contract if possible.",
                    details={"before": base_security, "after": revision_security},
                )
            ]

        return []

    def _compare_parameters(
        self,
        path: str,
        method: str,
        base_path_item: dict[str, Any],
        revision_path_item: dict[str, Any],
        base_operation: dict[str, Any],
        revision_operation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        base_params = self._collect_parameters(base_path_item, base_operation)
        revision_params = self._collect_parameters(revision_path_item, revision_operation)

        for key, revision_param in revision_params.items():
            base_param = base_params.get(key)
            if base_param is None and revision_param["required"]:
                changes.append(
                    self._build_change(
                        change_id="required_parameter_added",
                        severity="HIGH",
                        path=path,
                        method=method,
                        component="request",
                        message=(
                            f"{method} {path} added required {revision_param['in']} parameter "
                            f"'{revision_param['name']}'"
                        ),
                        why_it_matters="Existing clients do not send this value, so requests may start failing.",
                        recommended_action="Make new parameters optional first, or release them under a new API version.",
                        details=revision_param,
                    )
                )
                continue

            if base_param is None:
                continue

            if not base_param["required"] and revision_param["required"]:
                changes.append(
                    self._build_change(
                        change_id="parameter_became_required",
                        severity="HIGH",
                        path=path,
                        method=method,
                        component="request",
                        message=(
                            f"{method} {path} changed parameter '{revision_param['name']}' "
                            f"to required"
                        ),
                        why_it_matters="Clients omitting this parameter will break after rollout.",
                        recommended_action="Keep the parameter optional until clients have migrated.",
                        details={"before": base_param, "after": revision_param},
                    )
                )

            if base_param["type"] and revision_param["type"] and base_param["type"] != revision_param["type"]:
                changes.append(
                    self._build_change(
                        change_id="parameter_type_changed",
                        severity="HIGH",
                        path=path,
                        method=method,
                        component="request",
                        message=(
                            f"{method} {path} changed parameter '{revision_param['name']}' "
                            f"type from {base_param['type']} to {revision_param['type']}"
                        ),
                        why_it_matters="Clients serializing the old parameter type may produce invalid requests.",
                        recommended_action="Introduce a new parameter name or support both formats during migration.",
                        details={"before": base_param, "after": revision_param},
                    )
                )

        return changes

    def _compare_request_body(
        self,
        path: str,
        method: str,
        base_operation: dict[str, Any],
        revision_operation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        base_body = base_operation.get("requestBody") or {}
        revision_body = revision_operation.get("requestBody") or {}

        if base_body and revision_body and not base_body.get("required", False) and revision_body.get("required", False):
            changes.append(
                self._build_change(
                    change_id="request_body_became_required",
                    severity="HIGH",
                    path=path,
                    method=method,
                    component="request",
                    message=f"{method} {path} changed the request body from optional to required",
                    why_it_matters="Clients that currently omit the body will start failing.",
                    recommended_action="Roll out request-body requirements behind a compatibility window or new version.",
                )
            )

        base_schema = self._extract_json_schema(base_body)
        revision_schema = self._extract_json_schema(revision_body)
        changes.extend(
            self._compare_schema(
                base_schema=base_schema,
                revision_schema=revision_schema,
                path=path,
                method=method,
                component="request",
                schema_path="requestBody",
            )
        )
        return changes

    def _compare_responses(
        self,
        path: str,
        method: str,
        base_operation: dict[str, Any],
        revision_operation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        base_responses = base_operation.get("responses") or {}
        revision_responses = revision_operation.get("responses") or {}

        for status_code, base_response in base_responses.items():
            status = str(status_code)
            if not status.startswith("2"):
                continue

            revision_response = revision_responses.get(status_code) or revision_responses.get(status)
            if revision_response is None:
                changes.append(
                    self._build_change(
                        change_id="success_response_removed",
                        severity="HIGH",
                        path=path,
                        method=method,
                        component="response",
                        message=f"{method} {path} removed successful response {status}",
                        why_it_matters="Clients coded against this success path may no longer handle responses correctly.",
                        recommended_action="Add the new response in parallel before removing the old success contract.",
                        details={"status_code": status},
                    )
                )
                continue

            base_schema = self._extract_json_schema(base_response)
            revision_schema = self._extract_json_schema(revision_response)
            changes.extend(
                self._compare_schema(
                    base_schema=base_schema,
                    revision_schema=revision_schema,
                    path=path,
                    method=method,
                    component="response",
                    schema_path=f"responses.{status}",
                )
            )

        return changes

    def _compare_schema(
        self,
        *,
        base_schema: dict[str, Any] | None,
        revision_schema: dict[str, Any] | None,
        path: str,
        method: str,
        component: str,
        schema_path: str,
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not base_schema or not revision_schema:
            return changes

        base_type = self._schema_type(base_schema)
        revision_type = self._schema_type(revision_schema)
        if base_type and revision_type and base_type != revision_type:
            changes.append(
                self._build_change(
                    change_id=f"{component}_schema_type_changed",
                    severity="HIGH",
                    path=path,
                    method=method,
                    component=component,
                    message=(
                        f"{method} {path} changed {schema_path} type "
                        f"from {base_type} to {revision_type}"
                    ),
                    why_it_matters="Type changes can break deserialization and validation in existing clients.",
                    recommended_action="Version the schema change or support both shapes during migration.",
                    details={"schema_path": schema_path},
                )
            )
            return changes

        if base_type == "object" and revision_type == "object":
            base_properties = base_schema.get("properties") or {}
            revision_properties = revision_schema.get("properties") or {}
            base_required = set(base_schema.get("required") or [])
            revision_required = set(revision_schema.get("required") or [])

            for prop_name, base_prop_schema in base_properties.items():
                nested_path = f"{schema_path}.{prop_name}"
                revision_prop_schema = revision_properties.get(prop_name)
                if revision_prop_schema is None:
                    changes.append(
                        self._build_change(
                            change_id=f"{component}_property_removed",
                            severity="HIGH",
                            path=path,
                            method=method,
                            component=component,
                            message=f"{method} {path} removed property '{nested_path}'",
                            why_it_matters="Clients that read or write this property will break.",
                            recommended_action="Deprecate fields first and remove them only in a new API version.",
                            details={"schema_path": nested_path},
                        )
                    )
                    continue

                changes.extend(
                    self._compare_schema(
                        base_schema=base_prop_schema,
                        revision_schema=revision_prop_schema,
                        path=path,
                        method=method,
                        component=component,
                        schema_path=nested_path,
                    )
                )

            if component == "request":
                for prop_name in sorted(revision_required - base_required):
                    changes.append(
                        self._build_change(
                            change_id="request_required_property_added",
                            severity="HIGH",
                            path=path,
                            method=method,
                            component=component,
                            message=f"{method} {path} added required request property '{schema_path}.{prop_name}'",
                            why_it_matters="Existing clients do not send this field, so requests may start failing.",
                            recommended_action="Introduce new required fields behind a compatibility phase or version bump.",
                            details={"schema_path": f"{schema_path}.{prop_name}"},
                        )
                    )

        if base_type == "array" and revision_type == "array":
            changes.extend(
                self._compare_schema(
                    base_schema=base_schema.get("items") or {},
                    revision_schema=revision_schema.get("items") or {},
                    path=path,
                    method=method,
                    component=component,
                    schema_path=f"{schema_path}[]",
                )
            )

        return changes

    def _collect_parameters(self, path_item: dict[str, Any], operation: dict[str, Any]) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for param in (path_item.get("parameters") or []) + (operation.get("parameters") or []):
            if not isinstance(param, dict):
                continue
            name = param.get("name")
            location = param.get("in")
            if not name or not location:
                continue
            key = f"{location}:{name}"
            merged[key] = {
                "name": str(name),
                "in": str(location),
                "required": bool(param.get("required", False)),
                "type": self._schema_type(param.get("schema") or {}),
            }
        return merged

    def _resolve_security(self, spec: dict[str, Any], operation: dict[str, Any]) -> Any:
        if "security" in operation:
            return operation.get("security")
        return spec.get("security")

    def _normalize_security(self, security: Any) -> list[dict[str, list[str]]]:
        if not isinstance(security, list):
            return []

        normalized: list[dict[str, list[str]]] = []
        for entry in security:
            if not isinstance(entry, dict):
                continue
            normalized.append(
                {
                    str(scheme): sorted(str(scope) for scope in (scopes or []))
                    for scheme, scopes in sorted(entry.items())
                }
            )
        return normalized

    def _extract_json_schema(self, container: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(container, dict):
            return None

        content = container.get("content") or {}
        if not isinstance(content, dict):
            return None

        for media_type in ("application/json", "application/*+json"):
            media = content.get(media_type)
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                return media["schema"]

        for media in content.values():
            if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                return media["schema"]

        return None

    def _schema_type(self, schema: dict[str, Any] | None) -> str | None:
        if not isinstance(schema, dict):
            return None

        schema_type = schema.get("type")
        if isinstance(schema_type, list):
            return "|".join(sorted(str(item) for item in schema_type))
        if schema_type:
            return str(schema_type)
        if "properties" in schema:
            return "object"
        if "items" in schema:
            return "array"
        return None

    def _build_summary(self, changes: list[dict[str, Any]]) -> dict[str, Any]:
        by_id: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for change in changes:
            by_id[change["id"]] = by_id.get(change["id"], 0) + 1
            by_severity[change["severity"]] = by_severity.get(change["severity"], 0) + 1

        return {
            "total_breaking_changes": len(changes),
            "by_change_type": by_id,
            "by_severity": by_severity,
        }

    def _build_recommendations(self, changes: list[dict[str, Any]]) -> list[str]:
        recommendations: list[str] = []
        seen: set[str] = set()
        for change in changes:
            recommendation = change["recommended_action"]
            if recommendation not in seen:
                seen.add(recommendation)
                recommendations.append(recommendation)
        return recommendations

    def _build_change(
        self,
        *,
        change_id: str,
        severity: str,
        path: str,
        method: str | None,
        component: str,
        message: str,
        why_it_matters: str,
        recommended_action: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        fingerprint_source = f"{change_id}:{severity}:{method or '*'}:{path}:{message}"
        return {
            "id": change_id,
            "severity": severity,
            "path": path,
            "method": method,
            "component": component,
            "message": message,
            "why_it_matters": why_it_matters,
            "recommended_action": recommended_action,
            "details": details or {},
            "fingerprint": sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16],
        }
