"""Generate OWASP ZAP scan plans from stored OpenAPI specs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import yaml

from server.modules.pentest.openapi_state_policy import apply_openapi_state_policy
from server.modules.pentest.target_policy import validate_pentest_target


_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def _normalized_target(target_url: str) -> str:
    return target_url.rstrip("/")


def _include_regex(target_url: str, path: str) -> str:
    base = _normalized_target(target_url)
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base}{suffix}.*"


def _header_replacer_rule(
    *,
    header: str,
    value: str,
    url: str = "",
    description: str | None = None,
) -> dict[str, Any]:
    return {
        "description": description or f"Inject {header}",
        "url": url,
        "matchType": "req_header",
        "matchString": header,
        "replacementString": value,
        "matchRegex": False,
        "tokenProcessing": False,
    }


def _extra_header_env_name(header: str) -> str:
    safe = "".join(char if char.isalnum() else "_" for char in header.upper()).strip("_")
    return f"ZAP_EXTRA_HEADER_{safe or 'VALUE'}"


def _is_env_placeholder(value: str) -> bool:
    stripped = str(value or "").strip()
    return stripped.startswith("${") and stripped.endswith("}") and len(stripped) > 3


class ZapScanPlanBuilder:
    """Builds a CI-friendly ZAP automation plan from an OpenAPI spec."""

    def build(
        self,
        *,
        spec: dict[str, Any],
        target_url: str,
        spec_id: str | None = None,
        context_name: str = "api-sentinel",
        max_passive_wait_minutes: int = 5,
        active_scan_policy: str = "API Policy",
        fail_severity: str = "High",
        warn_severity: str = "Medium",
        auth_header_name: str | None = None,
        auth_header_site: str | None = None,
        extra_headers: dict[str, str] | None = None,
        allow_state_change: bool = False,
        allow_destructive_methods: bool = False,
    ) -> dict[str, Any]:
        validate_pentest_target(target_url)

        extra_headers = extra_headers or {}
        scoped_spec, state_change_policy = apply_openapi_state_policy(
            spec or {},
            allow_state_change=allow_state_change,
            allow_destructive_methods=allow_destructive_methods,
        )
        paths = scoped_spec.get("paths", {}) or {}
        operations: list[dict[str, Any]] = []
        include_paths: list[str] = []
        auth_required = 0
        active_scan_included = not (
            state_change_policy["input_operation_count"] > 0
            and state_change_policy["retained_operation_count"] == 0
        )

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            include_paths.append(_include_regex(target_url, path))
            for method in _HTTP_METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                requires_auth = bool(operation.get("security") or scoped_spec.get("security"))
                auth_required += 1 if requires_auth else 0
                operations.append(
                    {
                        "method": method.upper(),
                        "path": path,
                        "operation_id": operation.get("operationId"),
                        "requires_auth": requires_auth,
                        "summary": operation.get("summary"),
                    }
                )

        plan = {
            "env": {
                "contexts": [
                    {
                        "name": context_name,
                        "urls": [_normalized_target(target_url)],
                        "includePaths": include_paths or [f"{_normalized_target(target_url)}.*"],
                        "excludePaths": [],
                    }
                ],
                "parameters": {
                    "failOnError": True,
                    "failOnWarning": False,
                    "progressToStdout": True,
                },
            },
            "jobs": [
                {
                    "type": "openapi",
                    "parameters": {
                        "apiFile": "openapi.json",
                        "context": context_name,
                        "targetUrl": _normalized_target(target_url),
                    },
                },
            ],
        }

        replacer_rules: list[dict[str, Any]] = []
        if auth_header_name:
            replacer_rules.append(
                _header_replacer_rule(
                    header=auth_header_name,
                    value="${ZAP_AUTH_HEADER_VALUE}",
                    url=auth_header_site or "",
                    description=f"Inject {auth_header_name} from ZAP_AUTH_HEADER_VALUE",
                )
            )

        auth_header_key = auth_header_name.lower() if auth_header_name else None
        extra_required_env: list[dict[str, str]] = []
        for header, value in sorted(extra_headers.items()):
            if auth_header_key and header.lower() == auth_header_key:
                continue
            replacement_value = str(value)
            if not _is_env_placeholder(replacement_value):
                env_name = _extra_header_env_name(header)
                replacement_value = f"${{{env_name}}}"
                extra_required_env.append({"name": env_name, "value": "<set-in-ci>"})
            replacer_rules.append(_header_replacer_rule(header=header, value=replacement_value))

        if replacer_rules:
            plan["jobs"].append(
                {
                    "type": "replacer",
                    "parameters": {"deleteAllRules": False},
                    "rules": replacer_rules,
                }
            )

        plan["jobs"].append(
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": max(1, max_passive_wait_minutes)},
            }
        )
        if active_scan_included:
            plan["jobs"].append(
                {
                    "type": "activeScan",
                    "parameters": {
                        "context": context_name,
                        "policy": active_scan_policy,
                    },
                }
            )
            plan["jobs"].append(
                {
                    "type": "passiveScan-wait",
                    "parameters": {"maxDuration": max(1, max_passive_wait_minutes)},
                }
            )
        plan["jobs"].extend(
            [
                {
                    "type": "report",
                    "parameters": {
                        "template": "traditional-json",
                        "reportDir": ".",
                        "reportFile": "zap-report.json",
                    },
                },
                {
                    "type": "exitStatus",
                    "parameters": {
                        "errorLevel": fail_severity.title(),
                        "warnLevel": warn_severity.title(),
                        "okExitValue": 0,
                        "errorExitValue": 1,
                        "warnExitValue": 2,
                    },
                },
            ]
        )

        required_env = []
        if auth_header_name:
            required_env.extend(
                [
                    {"name": "ZAP_AUTH_HEADER", "value": auth_header_name},
                    {"name": "ZAP_AUTH_HEADER_VALUE", "value": "<set-in-ci>"},
                ]
            )
            if auth_header_site:
                required_env.append({"name": "ZAP_AUTH_HEADER_SITE", "value": auth_header_site})
        required_env.extend(extra_required_env)

        parsed_target = urlparse(_normalized_target(target_url))
        docker_command = (
            "docker run --rm -v ${PWD}:/zap/wrk -w /zap/wrk "
            "ghcr.io/zaproxy/zaproxy:stable "
            "zap.sh -cmd -autorun zap-plan.yaml"
        )

        return {
            "summary": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "spec_id": spec_id,
                "target_url": _normalized_target(target_url),
                "host": parsed_target.netloc,
                "path_count": len(paths),
                "operation_count": len(operations),
                "authenticated_operation_count": auth_required,
                "uses_header_auth_env": bool(auth_header_name),
                "uses_replacer_rules": bool(replacer_rules),
                "active_scan_included": active_scan_included,
                "state_change_filtered": bool(state_change_policy["filtered"]),
                "blocked_destructive_operation_count": state_change_policy["blocked_destructive_operation_count"],
            },
            "artifacts": {
                "openapi_filename": "openapi.json",
                "plan_filename": "zap-plan.yaml",
                "report_filename": "zap-report.json",
                "openapi_spec": scoped_spec,
                "automation_yaml": yaml.safe_dump(plan, sort_keys=False),
            },
            "execution": {
                "docker_command": docker_command,
                "local_command": "zap.sh -cmd -autorun zap-plan.yaml",
                "required_env": required_env,
            },
            "plan": plan,
            "operations": operations,
            "state_change_policy": state_change_policy,
            "recommendations": [
                "Run the plan with a disposable auth token scoped to test data.",
                "Prefer the built-in ZAP authentication header env vars for a single bearer-style header.",
                "Use replacer rules only when the target needs multiple custom headers.",
                "POST, PUT, PATCH, and DELETE operations require explicit destructive-method arming.",
            ],
        }
