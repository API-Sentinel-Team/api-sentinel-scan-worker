from types import SimpleNamespace

from sentinel_worker.modules.nuclei.runner import NucleiRunner
from sentinel_core.modules.pentest.engine_plan import build_engine_plan
from sentinel_worker.modules.pentest.schemathesis_runner import SchemathesisRunner
from sentinel_worker.modules.zap.runner import ZapRunner


def test_external_engine_readiness_requires_the_runtime_executable(monkeypatch):
    def fake_which(name):
        return {
            "nuclei": "C:/tools/nuclei.exe",
            "zap.cmd": "C:/tools/zap.cmd",
        }.get(name)

    monkeypatch.setattr(
        "sentinel_worker.modules.pentest.schemathesis_runner.shutil.which",
        fake_which,
    )

    assert SchemathesisRunner.is_available() is False
    assert NucleiRunner.is_available() is True
    assert ZapRunner.is_available() is True


def test_engine_plan_ready_requires_real_runtime_probe_not_profile_config():
    profile = SimpleNamespace(
        schemathesis_enabled=True,
        nuclei_enabled=True,
        zap_enabled=True,
    )
    auth_profile = SimpleNamespace(
        auth_mode="bearer",
        token="runtime-token",
        header_value=None,
        static_headers={},
    )

    plan = build_engine_plan(
        profile=profile,
        auth_profile=auth_profile,
        has_openapi_spec=True,
        schemathesis_available=False,
        nuclei_available=False,
        zap_available=False,
        require_authenticated_active_scan=True,
    )
    by_engine = {item["engine"]: item for item in plan}

    assert by_engine["templates"]["status"] == "ready"
    for engine in ("schemathesis", "nuclei", "zap"):
        assert by_engine[engine]["enabled"] is True
        assert by_engine[engine]["runtime_available"] is False
        assert by_engine[engine]["status"] == "blocked"
        assert by_engine[engine]["reason"] == "engine_runtime_unavailable"
