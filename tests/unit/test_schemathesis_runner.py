from types import SimpleNamespace
import json
import os
from pathlib import Path

import pytest

from sentinel_worker.modules.pentest.schemathesis_runner import SchemathesisRunner
from sentinel_core.modules.test_executor.target_guard import TargetGuardError


def _profile(
    *,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        schemathesis_workers=1,
        follow_redirects=False,
        request_timeout_seconds=5,
        schemathesis_stateful=False,
        schemathesis_max_examples=2,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )


def _auth_profile() -> SimpleNamespace:
    return SimpleNamespace(
        id="auth-1",
        auth_mode="bearer",
        openapi_security_scheme="BearerAuth",
        token="raw-token-123",
        header_value=None,
        header_name="Authorization",
        static_headers={"X-API-Key": "static-secret-456"},
        scope_domains=["api.example.com"],
    )


def _spec() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "Demo", "version": "1.0.0"},
        "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }


def test_schemathesis_config_exposes_env_names_without_values_by_default():
    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert payload["env_vars"] == [{"name": "SCHEMATHESIS_TOKEN"}]
    assert "raw-token-123" not in str(payload)
    assert "static-secret-456" not in str(payload)
    assert "unexpected-methods = []" in payload["content"]


def test_schemathesis_config_allows_unexpected_destructive_methods_only_with_destructive_opt_in():
    state_change_only = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(allow_state_change=True),
        auth_profile=_auth_profile(),
    )

    assert "unexpected-methods = []" in state_change_only["content"]

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(allow_state_change=True, allow_destructive_methods=True),
        auth_profile=_auth_profile(),
    )

    assert 'unexpected-methods = ["DELETE", "PATCH", "POST", "PUT"]' in payload["content"]


def test_schemathesis_config_uses_header_auth_when_openapi_scheme_is_missing():
    auth_profile = _auth_profile()
    auth_profile.openapi_security_scheme = None

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    env_names = {item["name"] for item in payload["env_vars"]}
    assert "Authorization" in payload["content"]
    assert "${SCHEMATHESIS_HEADER_VALUE}" in payload["content"]
    assert "${SCHEMATHESIS_STATIC_HEADER_X_API_KEY_1}" in payload["content"]
    assert {"SCHEMATHESIS_HEADER_VALUE", "SCHEMATHESIS_STATIC_HEADER_X_API_KEY_1"} <= env_names
    assert "raw-token-123" not in str(payload)
    assert "static-secret-456" not in str(payload)


def test_schemathesis_config_omits_empty_auth_header_material():
    auth_profile = _auth_profile()
    auth_profile.token = "Bearer "
    auth_profile.header_value = "   "
    auth_profile.static_headers = {"Authorization": "Basic ", "X-API-Key": "   "}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    assert payload["env_vars"] == []
    assert "SCHEMATHESIS_TOKEN" not in payload["content"]
    assert "SCHEMATHESIS_HEADER_VALUE" not in payload["content"]
    assert "SCHEMATHESIS_STATIC_HEADER" not in payload["content"]


def test_schemathesis_config_omits_empty_basic_auth_material():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "basic"
    auth_profile.username = ""
    auth_profile.password = "   "
    auth_profile.static_headers = {}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    assert payload["env_vars"] == []
    assert "[auth.openapi.BearerAuth]" not in payload["content"]
    assert "SCHEMATHESIS_USERNAME" not in payload["content"]
    assert "SCHEMATHESIS_PASSWORD" not in payload["content"]


def test_schemathesis_config_emits_cookie_auth_header():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "cookie"
    auth_profile.cookies = [{"key": "session", "value": "cookie-secret"}]
    auth_profile.cookie_name = "tenant"
    auth_profile.cookie_value = "tenant-secret"
    auth_profile.token = None
    auth_profile.header_value = None
    auth_profile.static_headers = {}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    assert payload["env_vars"] == [{"name": "SCHEMATHESIS_COOKIE_HEADER"}]
    assert 'headers = { "Cookie" = "${SCHEMATHESIS_COOKIE_HEADER}" }' in payload["content"]
    assert "cookie-secret" not in str(payload)
    assert "tenant-secret" not in str(payload)


def test_schemathesis_config_omits_dynamic_auth_without_login_material():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "dynamic_bearer"
    auth_profile.login_url = "https://api.example.com/auth/token"
    auth_profile.login_method = "POST"
    auth_profile.token_json_path = "/access_token"
    auth_profile.username = " "
    auth_profile.password = ""
    auth_profile.login_payload = {}
    auth_profile.login_headers = {}
    auth_profile.token = None
    auth_profile.header_value = None
    auth_profile.static_headers = {}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    assert payload["env_vars"] == []
    assert "[auth.dynamic.openapi.BearerAuth]" not in payload["content"]
    assert "extract_selector" not in payload["content"]
    assert "SCHEMATHESIS_USERNAME" not in payload["content"]
    assert "SCHEMATHESIS_LOGIN_HEADER" not in payload["content"]


def test_schemathesis_config_emits_dynamic_auth_with_login_credentials():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "dynamic_bearer"
    auth_profile.login_url = "https://api.example.com/auth/token"
    auth_profile.login_method = "POST"
    auth_profile.token_json_path = "/access_token"
    auth_profile.username = "api-user"
    auth_profile.password = "api-password"
    auth_profile.login_payload = {}
    auth_profile.login_headers = {}
    auth_profile.token = None
    auth_profile.header_value = None
    auth_profile.static_headers = {}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    env_names = {item["name"] for item in payload["env_vars"]}
    assert "[auth.dynamic.openapi.BearerAuth]" in payload["content"]
    assert "extract_selector = \"/access_token\"" in payload["content"]
    assert "payload = { \"username\" = \"${SCHEMATHESIS_USERNAME}\", \"password\" = \"${SCHEMATHESIS_PASSWORD}\" }" in payload["content"]
    assert {"SCHEMATHESIS_USERNAME", "SCHEMATHESIS_PASSWORD"} <= env_names
    assert "api-password" not in str(payload)


def test_schemathesis_config_emits_oauth_client_credentials_payload():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "oauth"
    auth_profile.login_url = "https://api.example.com/oauth/token"
    auth_profile.login_method = "POST"
    auth_profile.token_json_path = "/access_token"
    auth_profile.username = ""
    auth_profile.password = ""
    auth_profile.login_payload = {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "secret-1",
    }
    auth_profile.login_headers = {"Content-Type": "application/json"}
    auth_profile.token = None
    auth_profile.header_value = None
    auth_profile.static_headers = {}

    payload = SchemathesisRunner().build_config(
        target_url="https://api.example.com",
        profile=_profile(),
        auth_profile=auth_profile,
    )

    env_names = {item["name"] for item in payload["env_vars"]}
    assert "[auth.dynamic.openapi.BearerAuth]" in payload["content"]
    assert 'path = "/oauth/token"' in payload["content"]
    assert "SCHEMATHESIS_LOGIN_PAYLOAD_CLIENT_ID_2" in env_names
    assert "SCHEMATHESIS_LOGIN_PAYLOAD_CLIENT_SECRET_3" in env_names
    assert "SCHEMATHESIS_LOGIN_HEADER_CONTENT_TYPE_1" in env_names
    assert "secret-1" not in str(payload)


@pytest.mark.asyncio
async def test_schemathesis_run_skips_without_cli_without_leaking_env_values(monkeypatch):
    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: None))

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "SKIPPED"
    assert result["reason"] == "schemathesis_cli_missing"
    assert result["env_var_names"] == ["SCHEMATHESIS_TOKEN"]
    assert "raw-token-123" not in str(result)
    assert "static-secret-456" not in str(result)


@pytest.mark.asyncio
async def test_schemathesis_run_blocks_target_guard_before_cli_lookup(monkeypatch):
    def fail_cli_lookup():
        raise AssertionError("cli lookup should not happen before target validation")

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(fail_cli_lookup))

    with pytest.raises(TargetGuardError):
        await SchemathesisRunner().run_scan(
            target_url="http://169.254.169.254/latest/meta-data",
            openapi_spec=_spec(),
            profile=_profile(),
            auth_profile=_auth_profile(),
        )


@pytest.mark.asyncio
async def test_schemathesis_run_uses_no_shell_and_redacts_process_evidence(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 1

        async def communicate(self):
            return (b"Authorization: Bearer raw-token-123", b"token=raw-token-123")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        captured["cwd"] = kwargs["cwd"]
        report_path = os.path.join(kwargs["cwd"], "schemathesis-junit.xml")
        with open(report_path, "w", encoding="utf-8") as report:
            report.write(
                """<testsuite name="schemathesis" tests="1" failures="1">
  <testcase classname="schemathesis" name="GET /users?token=raw-token-123">
    <failure type="ignored_auth" message="Authorization: Bearer raw-token-123">token=raw-token-123</failure>
  </testcase>
</testsuite>
"""
            )
        return FakeProcess()

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "FAILED_WITH_FINDINGS"
    assert result["failures"] == 1
    assert captured["args"] == (
        "schemathesis",
        "run",
        "openapi.json",
        "--config",
        "schemathesis.toml",
        "--junit-xml",
        "schemathesis-junit.xml",
    )
    assert captured["env"]["SCHEMATHESIS_TOKEN"] == "raw-token-123"
    assert "raw-token-123" not in str(result)
    assert "Bearer ****" in result["stdout"]
    assert "token=****" in result["stderr"]


@pytest.mark.asyncio
async def test_schemathesis_run_uses_worker_isolation_sandbox_for_subprocess_cwd(tmp_path, monkeypatch):
    sandbox = tmp_path / "workers" / "schemathesis-sandbox"
    sandbox.mkdir(parents=True)
    captured = {}

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*_args, **kwargs):
        captured["cwd"] = kwargs["cwd"]
        return FakeProcess()

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
        worker_isolation_context={
            "sandbox_path": str(sandbox),
            "env": {"API_SENTINEL_WORKER_ID": "worker-1"},
            "resource_limits": {"cpu": "1000m", "memory": "1Gi", "ephemeral_storage": "2Gi"},
        },
    )

    assert result["status"] == "COMPLETED"
    assert captured["cwd"]
    assert Path(captured["cwd"]).resolve().is_relative_to(sandbox.resolve())
    enforcement = result["worker_isolation_enforcement"]
    assert enforcement["present"] is True
    assert enforcement["subprocess_cwd_confined_to_sandbox"] is True
    assert enforcement["env_names"] == ["API_SENTINEL_WORKER_ID"]


@pytest.mark.asyncio
async def test_schemathesis_run_returns_redacted_launch_failure(monkeypatch):
    async def fake_create_subprocess_exec(*_args, **_kwargs):
        raise OSError("failed with token=raw-token-123")

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "FAILED"
    assert result["reason"] == "schemathesis_launch_failed"
    assert "raw-token-123" not in str(result)
    assert "token=****" in result["stderr"]


@pytest.mark.asyncio
async def test_schemathesis_run_filters_state_changing_openapi_operations(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers"},
                "post": {"operationId": "createUser"},
            }
        },
    }

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*_args, **kwargs):
        with open(os.path.join(kwargs["cwd"], "openapi.json"), encoding="utf-8") as spec_file:
            captured["spec"] = json.load(spec_file)
        return FakeProcess()

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=spec,
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "COMPLETED"
    assert captured["spec"]["paths"] == {"/users": {"get": {"operationId": "listUsers"}}}
    assert result["state_change_policy"]["filtered"] is True
    assert result["state_change_policy"]["blocked_operation_count"] == 1
    assert result["state_change_policy"]["blocked_operations"][0]["method"] == "POST"


@pytest.mark.asyncio
async def test_schemathesis_run_blocks_destructive_operations_without_destructive_opt_in(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {"operationId": "createUser"},
                "delete": {"operationId": "deleteUsers"},
            }
        },
    }

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*_args, **kwargs):
        with open(os.path.join(kwargs["cwd"], "openapi.json"), encoding="utf-8") as spec_file:
            captured["spec"] = json.load(spec_file)
        return FakeProcess()

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=spec,
        profile=_profile(allow_state_change=True),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "SKIPPED"
    assert "spec" not in captured
    assert result["state_change_policy"]["allow_state_change"] is True
    assert result["state_change_policy"]["allow_destructive_methods"] is False
    assert result["state_change_policy"]["blocked_destructive_operations"] == [
        {"method": "POST", "path": "/users", "operation_id": "createUser"},
        {"method": "DELETE", "path": "/users", "operation_id": "deleteUsers"},
    ]


@pytest.mark.asyncio
async def test_schemathesis_run_keeps_destructive_operations_with_destructive_opt_in(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {"operationId": "createUser"},
                "delete": {"operationId": "deleteUsers"},
            }
        },
    }

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*_args, **kwargs):
        with open(os.path.join(kwargs["cwd"], "openapi.json"), encoding="utf-8") as spec_file:
            captured["spec"] = json.load(spec_file)
        return FakeProcess()

    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))
    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=spec,
        profile=_profile(allow_state_change=True, allow_destructive_methods=True),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "COMPLETED"
    assert captured["spec"] == spec
    assert result["state_change_policy"]["allow_destructive_methods"] is True
    assert result["state_change_policy"]["blocked_destructive_operations"] == []


@pytest.mark.asyncio
async def test_schemathesis_run_skips_when_safe_mode_removes_all_openapi_operations(monkeypatch):
    monkeypatch.setattr(SchemathesisRunner, "cli_path", staticmethod(lambda: "schemathesis"))

    result = await SchemathesisRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec={
            "openapi": "3.0.0",
            "paths": {"/users": {"post": {"operationId": "createUser"}}},
        },
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "SKIPPED"
    assert result["reason"] == "state_change_policy_no_safe_operations"
    assert result["state_change_policy"]["retained_operation_count"] == 0
