from types import SimpleNamespace
import json
import os
from pathlib import Path

import pytest

from sentinel_core.modules.test_executor.target_guard import TargetGuardError
from sentinel_worker.modules.zap.runner import ZapRunner, _build_auth_material


def _profile(
    *,
    allow_state_change: bool = False,
    allow_destructive_methods: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        request_timeout_seconds=5,
        follow_redirects=False,
        zap_enabled=True,
        allow_state_change=allow_state_change,
        allow_destructive_methods=allow_destructive_methods,
    )


def _auth_profile() -> SimpleNamespace:
    return SimpleNamespace(
        id="auth-1",
        auth_mode="bearer",
        header_name="Authorization",
        token="raw-token-123",
        header_value=None,
        username=None,
        password=None,
        cookie_name=None,
        cookie_value=None,
        cookies=[],
        static_headers={"X-Tenant": "tenant-secret-456"},
        login_headers={},
        scope_domains=["api.example.com"],
    )


def _spec() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "Demo", "version": "1.0.0"},
        "paths": {"/search": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }


def test_zap_auth_material_omits_blank_header_values():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "header"
    auth_profile.token = "   "
    auth_profile.header_value = "Bearer "
    auth_profile.static_headers = {"Authorization": "Basic ", "X-API-Key": "   "}

    material = _build_auth_material(
        auth_profile=auth_profile,
        target_url="https://api.example.com",
    )

    assert material["auth_header_name"] is None
    assert material["extra_headers"] == {}
    assert material["env_vars"] == []


def test_zap_auth_material_omits_blank_basic_and_cookie_values():
    basic_profile = _auth_profile()
    basic_profile.auth_mode = "basic"
    basic_profile.username = "api-user"
    basic_profile.password = "   "
    basic_profile.static_headers = {}

    cookie_profile = _auth_profile()
    cookie_profile.auth_mode = "cookie"
    cookie_profile.cookies = [{"key": "session", "value": "   "}]
    cookie_profile.cookie_name = "fallback"
    cookie_profile.cookie_value = ""
    cookie_profile.static_headers = {}

    basic_material = _build_auth_material(
        auth_profile=basic_profile,
        target_url="https://api.example.com",
    )
    cookie_material = _build_auth_material(
        auth_profile=cookie_profile,
        target_url="https://api.example.com",
    )

    assert basic_material["env_vars"] == []
    assert basic_material["auth_header_name"] is None
    assert cookie_material["env_vars"] == []
    assert cookie_material["auth_header_name"] is None


def test_zap_dynamic_bearer_with_bare_scheme_is_not_materialized():
    auth_profile = _auth_profile()
    auth_profile.auth_mode = "dynamic_bearer"
    auth_profile.token = "Bearer "
    auth_profile.header_value = ""
    auth_profile.static_headers = {}

    material = _build_auth_material(
        auth_profile=auth_profile,
        target_url="https://api.example.com",
    )

    assert material["unsupported_reason"] == "zap_dynamic_auth_not_supported"
    assert material["env_vars"] == []


@pytest.mark.asyncio
async def test_zap_run_skips_without_cli_without_leaking_env_values(monkeypatch):
    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: None))

    result = await ZapRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "SKIPPED"
    assert result["reason"] == "zap_cli_missing"
    assert "ZAP_AUTH_HEADER_VALUE" in result["env_var_names"]
    assert "raw-token-123" not in str(result)
    assert "tenant-secret-456" not in str(result)


@pytest.mark.asyncio
async def test_zap_run_blocks_target_guard_before_cli_lookup(monkeypatch):
    def fail_cli_lookup():
        raise AssertionError("cli lookup should not happen before target validation")

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(fail_cli_lookup))

    with pytest.raises(TargetGuardError):
        await ZapRunner().run_scan(
            target_url="http://169.254.169.254/latest/meta-data",
            openapi_spec=_spec(),
            profile=_profile(),
            auth_profile=_auth_profile(),
        )


@pytest.mark.asyncio
async def test_zap_run_uses_no_shell_and_redacts_process_and_report(monkeypatch):
    captured = {}

    class FakeProcess:
        returncode = 1

        async def communicate(self):
            return (b"Authorization: Bearer raw-token-123", b"token=raw-token-123")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        report_path = os.path.join(kwargs["cwd"], "zap-report.json")
        with open(report_path, "w", encoding="utf-8") as report:
            report.write(
                """{
  "site": [{
    "@name": "https://api.example.com",
    "alerts": [{
      "pluginid": "40012",
      "alert": "Cross Site Scripting",
      "riskdesc": "High (Medium)",
      "confidence": "High",
      "instances": [{
        "uri": "https://api.example.com/search?q=x&token=raw-token-123",
        "method": "GET",
        "evidence": "Authorization: Bearer raw-token-123"
      }]
    }]
  }]
}
"""
            )
        return FakeProcess()

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "FAILED_WITH_FINDINGS"
    assert result["alerts"] == 1
    assert captured["args"] == ("zap.sh", "-cmd", "-autorun", "zap-plan.yaml")
    assert captured["env"]["ZAP_AUTH_HEADER_VALUE"] == "Bearer raw-token-123"
    assert captured["env"]["ZAP_STATIC_HEADER_X_TENANT_1"] == "tenant-secret-456"
    assert "raw-token-123" not in str(result)
    assert "tenant-secret-456" not in str(result)
    assert "****" in result["stdout"]
    assert "token=****" in result["stderr"]
    instance = result["report"]["site"][0]["alerts"][0]["instances"][0]
    assert instance["uri"] == "https://api.example.com/search?q=****&token=****"
    assert "****" in instance["evidence"]


@pytest.mark.asyncio
async def test_zap_run_uses_worker_isolation_sandbox_for_subprocess_cwd(tmp_path, monkeypatch):
    sandbox = tmp_path / "workers" / "zap-sandbox"
    sandbox.mkdir(parents=True)
    captured = {}

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*_args, **kwargs):
        captured["cwd"] = kwargs["cwd"]
        return FakeProcess()

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
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
async def test_zap_run_returns_redacted_launch_failure(monkeypatch):
    async def fake_create_subprocess_exec(*_args, **_kwargs):
        raise OSError("failed with token=raw-token-123")

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=_spec(),
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "FAILED"
    assert result["reason"] == "zap_launch_failed"
    assert "raw-token-123" not in str(result)
    assert "token=****" in result["stderr"]


@pytest.mark.asyncio
async def test_zap_run_filters_state_changing_openapi_operations(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/search": {
                "get": {"operationId": "search"},
                "delete": {"operationId": "deleteSearch"},
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

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
        target_url="https://api.example.com",
        openapi_spec=spec,
        profile=_profile(),
        auth_profile=_auth_profile(),
    )

    assert result["status"] == "COMPLETED"
    assert captured["spec"]["paths"] == {"/search": {"get": {"operationId": "search"}}}
    assert result["state_change_policy"]["filtered"] is True
    assert result["state_change_policy"]["blocked_operations"][0]["method"] == "DELETE"


@pytest.mark.asyncio
async def test_zap_run_blocks_destructive_operations_without_destructive_opt_in(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/search": {
                "post": {"operationId": "createSearch"},
                "delete": {"operationId": "deleteSearch"},
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

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
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
        {"method": "POST", "path": "/search", "operation_id": "createSearch"},
        {"method": "DELETE", "path": "/search", "operation_id": "deleteSearch"},
    ]


@pytest.mark.asyncio
async def test_zap_run_keeps_destructive_operations_with_destructive_opt_in(monkeypatch):
    captured = {}
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/search": {
                "post": {"operationId": "createSearch"},
                "delete": {"operationId": "deleteSearch"},
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

    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))
    monkeypatch.setattr(
        "sentinel_worker.modules.zap.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await ZapRunner().run_scan(
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
async def test_zap_run_skips_when_safe_mode_removes_all_openapi_operations(monkeypatch):
    monkeypatch.setattr(ZapRunner, "cli_path", staticmethod(lambda: "zap.sh"))

    result = await ZapRunner().run_scan(
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
