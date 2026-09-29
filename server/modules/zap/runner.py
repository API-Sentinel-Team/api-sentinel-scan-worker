from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import re
import shutil
import tempfile
import uuid
from typing import Any

from server.config import settings
from server.models.core import AuthProfile, PentestProfile
from server.modules.api_inventory.zap_plan import ZapScanPlanBuilder
from server.modules.pentest.auth_material import (
    auth_header_value_has_material,
    first_auth_header_value,
    normalized_text,
    present,
)
from server.modules.pentest.auth_scope import validate_auth_profile_scope
from server.modules.pentest.openapi_state_policy import apply_openapi_state_policy
from server.modules.pentest.target_policy import validate_pentest_target
from server.modules.pentest.worker_isolation import (
    worker_isolation_child_work_root,
    worker_isolation_enforcement_metadata,
    worker_isolation_subprocess_env,
)
from server.modules.utils.redactor import Redactor
from server.modules.zap.findings import iter_zap_alert_instances


class ZapRunner:
    """Run OWASP ZAP automation plans with guarded targets and redacted evidence."""

    @staticmethod
    def cli_path() -> str | None:
        for candidate in ("zap.sh", "zap.cmd", "zap.bat"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return None

    @classmethod
    def is_available(cls) -> bool:
        return cls.cli_path() is not None

    async def run_scan(
        self,
        *,
        target_url: str,
        openapi_spec: dict[str, Any],
        profile: PentestProfile,
        auth_profile: AuthProfile | None = None,
        timeout_seconds: int | None = None,
        worker_isolation_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validate_pentest_target(target_url)
        if not isinstance(openapi_spec, dict) or not openapi_spec:
            raise ValueError("openapi_spec is required for ZAP execution")
        scoped_spec, state_change_policy = apply_openapi_state_policy(
            openapi_spec,
            allow_state_change=bool(getattr(profile, "allow_state_change", False)),
            allow_destructive_methods=bool(getattr(profile, "allow_destructive_methods", False)),
        )

        auth_material = _build_auth_material(auth_profile=auth_profile, target_url=target_url)
        env_vars = auth_material["env_vars"]
        env_var_names = [item["name"] for item in env_vars]
        cli_path = self.cli_path()
        command = "zap.sh -cmd -autorun zap-plan.yaml"
        secret_values = _secret_values_from_auth(auth_profile, env_vars=env_vars)
        isolation_enforcement = worker_isolation_enforcement_metadata(
            worker_isolation_context,
            engine="zap",
        )

        if auth_material.get("unsupported_reason"):
            return {
                "status": "SKIPPED",
                "reason": auth_material["unsupported_reason"],
                "message": "ZAP direct execution requires static header, bearer, basic, or cookie auth material.",
                "command": command,
                "env_var_names": env_var_names,
                "state_change_policy": state_change_policy,
                "report": {},
                "alerts": 0,
                "worker_isolation_enforcement": isolation_enforcement,
            }
        if state_change_policy["input_operation_count"] and state_change_policy["retained_operation_count"] == 0:
            return {
                "status": "SKIPPED",
                "reason": "state_change_policy_no_safe_operations",
                "message": "ZAP live scan skipped because safe mode removed every state-changing OpenAPI operation.",
                "command": command,
                "env_var_names": env_var_names,
                "state_change_policy": state_change_policy,
                "report": {},
                "alerts": 0,
                "worker_isolation_enforcement": isolation_enforcement,
            }
        if not cli_path:
            return {
                "status": "SKIPPED",
                "reason": "zap_cli_missing",
                "message": "OWASP ZAP CLI is not installed; live scan skipped.",
                "command": command,
                "env_var_names": env_var_names,
                "state_change_policy": state_change_policy,
                "report": {},
                "alerts": 0,
                "worker_isolation_enforcement": isolation_enforcement,
            }

        plan = ZapScanPlanBuilder().build(
            spec=scoped_spec,
            target_url=target_url,
            spec_id=None,
            auth_header_name=auth_material.get("auth_header_name"),
            auth_header_site=target_url if auth_material.get("auth_header_name") else None,
            extra_headers=auth_material.get("extra_headers") or {},
        )
        timeout = int(timeout_seconds or settings.PENTEST_ZAP_TIMEOUT_SECONDS)

        with _scan_workdir(worker_isolation_context=worker_isolation_context) as workdir:
            isolation_enforcement = worker_isolation_enforcement_metadata(
                worker_isolation_context,
                engine="zap",
                cwd=workdir,
            )
            spec_path = os.path.join(workdir, "openapi.json")
            plan_path = os.path.join(workdir, "zap-plan.yaml")
            report_path = os.path.join(workdir, "zap-report.json")
            with open(spec_path, "w", encoding="utf-8") as spec_file:
                json.dump(scoped_spec, spec_file, ensure_ascii=False)
            with open(plan_path, "w", encoding="utf-8") as plan_file:
                plan_file.write(plan["artifacts"]["automation_yaml"])

            env = worker_isolation_subprocess_env(worker_isolation_context, os.environ.copy()) or os.environ.copy()
            for item in env_vars:
                env[item["name"]] = str(item.get("value") or "")

            try:
                process = await asyncio.create_subprocess_exec(
                    cli_path,
                    "-cmd",
                    "-autorun",
                    "zap-plan.yaml",
                    cwd=workdir,
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except OSError as exc:
                return {
                    "status": "FAILED",
                    "reason": "zap_launch_failed",
                    "exit_code": None,
                    "command": command,
                    "env_var_names": env_var_names,
                    "state_change_policy": state_change_policy,
                    "stderr": _redact_output(str(exc), secret_values),
                    "report": {},
                    "alerts": 0,
                    "worker_isolation_enforcement": isolation_enforcement,
                }

            stdout_bytes = b""
            stderr_bytes = b""
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.CancelledError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.communicate()
                raise
            except asyncio.TimeoutError:
                process.kill()
                with contextlib.suppress(Exception):
                    stdout_bytes, stderr_bytes = await process.communicate()
                report = _read_redacted_report(report_path, secret_values)
                return {
                    "status": "TIMEOUT",
                    "reason": "zap_timeout",
                    "timeout_seconds": timeout,
                    "exit_code": None,
                    "command": command,
                    "env_var_names": env_var_names,
                    "state_change_policy": state_change_policy,
                    "stdout": _redact_output(stdout_bytes.decode("utf-8", errors="replace"), secret_values),
                    "stderr": _redact_output(stderr_bytes.decode("utf-8", errors="replace"), secret_values),
                    "report": report,
                    "alerts": _count_alert_instances(report),
                    "worker_isolation_enforcement": isolation_enforcement,
                }

            report = _read_redacted_report(report_path, secret_values)
            alert_count = _count_alert_instances(report)
            exit_code = process.returncode
            status = "COMPLETED"
            if exit_code != 0:
                status = "FAILED_WITH_FINDINGS" if alert_count else "FAILED"

            return {
                "status": status,
                "exit_code": exit_code,
                "command": command,
                "env_var_names": env_var_names,
                "state_change_policy": state_change_policy,
                "stdout": _redact_output(stdout_bytes.decode("utf-8", errors="replace"), secret_values),
                "stderr": _redact_output(stderr_bytes.decode("utf-8", errors="replace"), secret_values),
                "report": report,
                "alerts": alert_count,
                "worker_isolation_enforcement": isolation_enforcement,
            }


def _build_auth_material(*, auth_profile: AuthProfile | None, target_url: str) -> dict[str, Any]:
    if auth_profile is None:
        return {"auth_header_name": None, "extra_headers": {}, "env_vars": []}

    validate_auth_profile_scope(auth_profile, target_url)
    mode = (auth_profile.auth_mode or "header").lower()
    env_vars: list[dict[str, str]] = []
    extra_headers: dict[str, str] = {}
    auth_header_name = None

    if mode == "bearer" or (
        mode == "oauth" and first_auth_header_value(auth_profile.token, auth_profile.header_value)
    ):
        raw_token = first_auth_header_value(auth_profile.token, auth_profile.header_value)
        if raw_token:
            auth_header_name = auth_profile.header_name or "Authorization"
            auth_value = raw_token if raw_token.lower().startswith("bearer ") else f"Bearer {raw_token}"
            env_vars.append({"name": "ZAP_AUTH_HEADER_VALUE", "value": auth_value})
            env_vars.append({"name": "ZAP_AUTH_HEADER", "value": auth_header_name})
            env_vars.append({"name": "ZAP_AUTH_HEADER_SITE", "value": target_url.rstrip("/")})
    elif mode == "basic":
        username = normalized_text(auth_profile.username)
        password = normalized_text(auth_profile.password)
        if present(username) and present(password):
            auth_header_name = "Authorization"
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            env_vars.append({"name": "ZAP_AUTH_HEADER_VALUE", "value": f"Basic {token}"})
            env_vars.append({"name": "ZAP_AUTH_HEADER", "value": auth_header_name})
            env_vars.append({"name": "ZAP_AUTH_HEADER_SITE", "value": target_url.rstrip("/")})
    elif mode == "cookie":
        cookie_header = _cookie_header(auth_profile)
        if cookie_header:
            auth_header_name = "Cookie"
            env_vars.append({"name": "ZAP_AUTH_HEADER_VALUE", "value": cookie_header})
            env_vars.append({"name": "ZAP_AUTH_HEADER", "value": auth_header_name})
            env_vars.append({"name": "ZAP_AUTH_HEADER_SITE", "value": target_url.rstrip("/")})
    elif mode == "header":
        header_name = auth_profile.header_name or "Authorization"
        header_value = first_auth_header_value(auth_profile.header_value, auth_profile.token)
        if header_value:
            auth_header_name = header_name
            env_vars.append({"name": "ZAP_AUTH_HEADER_VALUE", "value": header_value})
            env_vars.append({"name": "ZAP_AUTH_HEADER", "value": auth_header_name})
            env_vars.append({"name": "ZAP_AUTH_HEADER_SITE", "value": target_url.rstrip("/")})
    elif mode in {"dynamic_bearer", "oauth"}:
        raw_token = first_auth_header_value(auth_profile.token, auth_profile.header_value)
        if raw_token:
            auth_header_name = auth_profile.header_name or "Authorization"
            auth_value = raw_token if raw_token.lower().startswith("bearer ") else f"Bearer {raw_token}"
            env_vars.append({"name": "ZAP_AUTH_HEADER_VALUE", "value": auth_value})
            env_vars.append({"name": "ZAP_AUTH_HEADER", "value": auth_header_name})
            env_vars.append({"name": "ZAP_AUTH_HEADER_SITE", "value": target_url.rstrip("/")})
        else:
            return {"unsupported_reason": "zap_dynamic_auth_not_supported", "env_vars": [], "extra_headers": {}}

    for index, (key, value) in enumerate((auth_profile.static_headers or {}).items(), start=1):
        if not present(key) or not auth_header_value_has_material(value):
            continue
        if auth_header_name and str(key).lower() == auth_header_name.lower():
            continue
        name = _env_name("ZAP_STATIC_HEADER", str(key), index)
        extra_headers[str(key)] = f"${{{name}}}"
        env_vars.append({"name": name, "value": normalized_text(value)})

    return {
        "auth_header_name": auth_header_name,
        "extra_headers": extra_headers,
        "env_vars": env_vars,
    }


def _cookie_header(auth_profile: AuthProfile) -> str:
    cookies = []
    for cookie in auth_profile.cookies or []:
        if isinstance(cookie, dict) and present(cookie.get("key")) and present(cookie.get("value")):
            cookies.append(f"{normalized_text(cookie['key'])}={normalized_text(cookie.get('value'))}")
    if present(auth_profile.cookie_name) and present(auth_profile.cookie_value):
        cookies.append(f"{normalized_text(auth_profile.cookie_name)}={normalized_text(auth_profile.cookie_value)}")
    return "; ".join(cookies)


def _env_name(prefix: str, key: str, index: int) -> str:
    slug = re.sub(r"[^A-Z0-9]+", "_", str(key).upper()).strip("_")[:48]
    return f"{prefix}_{slug or 'HEADER'}_{index}"


@contextlib.contextmanager
def _scan_workdir(worker_isolation_context: dict[str, Any] | None = None):
    isolated_root = worker_isolation_child_work_root(worker_isolation_context, "zap")
    work_root = os.path.abspath(
        str(isolated_root or getattr(settings, "PENTEST_SCAN_WORK_DIR", "") or tempfile.gettempdir())
    )
    os.makedirs(work_root, exist_ok=True)
    workdir = os.path.abspath(os.path.join(work_root, f"api-sentinel-zap-{uuid.uuid4().hex}"))
    if os.path.commonpath([work_root, workdir]) != work_root:
        raise ValueError("invalid ZAP work directory")
    os.makedirs(workdir, exist_ok=False)
    try:
        yield workdir
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _secret_values_from_auth(
    auth_profile: AuthProfile | None,
    *,
    env_vars: list[dict[str, str]],
) -> list[str]:
    non_secret_env_names = {"ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_SITE"}
    values = [
        str(item.get("value") or "")
        for item in env_vars
        if str(item.get("name") or "") not in non_secret_env_names
    ]
    if auth_profile is not None:
        for attr in ("token", "header_value", "password", "cookie_value"):
            value = getattr(auth_profile, attr, None)
            if value:
                values.append(str(value))
        for headers in (getattr(auth_profile, "static_headers", None) or {}, getattr(auth_profile, "login_headers", None) or {}):
            if isinstance(headers, dict):
                values.extend(str(value) for value in headers.values() if value)
        for cookie in getattr(auth_profile, "cookies", None) or []:
            if isinstance(cookie, dict) and cookie.get("value"):
                values.append(str(cookie["value"]))
    return sorted({value for value in values if len(value) >= 3}, key=len, reverse=True)


def _redact_output(text: str, secret_values: list[str]) -> str:
    return Redactor.redact_text(_replace_secret_values(text, secret_values))[:12000]


def _replace_secret_values(text: str, secret_values: list[str]) -> str:
    redacted = text
    for value in secret_values:
        redacted = redacted.replace(value, Redactor.REDACT_VALUE)
    return redacted


def _read_redacted_report(path: str, secret_values: list[str]) -> dict[str, Any]:
    if not os.path.exists(path):
        return {}
    max_bytes = int(settings.PENTEST_ZAP_REPORT_MAX_BYTES)
    if os.path.getsize(path) > max_bytes:
        return {}
    with open(path, "r", encoding="utf-8", errors="replace") as report_file:
        raw_report = report_file.read()
    try:
        parsed = json.loads(raw_report)
    except json.JSONDecodeError:
        return {}
    return _redact_zap_report(parsed, secret_values=secret_values)


def _redact_zap_report(value: Any, *, secret_values: list[str], key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            item_key: _redact_zap_report(item_value, secret_values=secret_values, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_zap_report(item, secret_values=secret_values) for item in value]
    if isinstance(value, str):
        redacted = _replace_secret_values(value, secret_values)
        if key.lower() in {"uri", "url", "@name"} and redacted.lower().startswith(("http://", "https://")):
            return Redactor.redact_url(redacted)
        return Redactor.redact_text(redacted)
    return value


def _count_alert_instances(report: dict[str, Any]) -> int:
    if not report:
        return 0
    return sum(1 for _alert, _instance, _site in iter_zap_alert_instances(report))
