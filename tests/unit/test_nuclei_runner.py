import pytest
from pathlib import Path

from sentinel_worker.modules.nuclei.runner import NucleiRunner
from sentinel_core.modules.test_executor.target_guard import TargetGuardError


@pytest.mark.asyncio
async def test_nuclei_runner_fails_closed_without_binary(monkeypatch):
    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: False))

    result = await NucleiRunner.run_scan("https://api.example.com")

    assert result["status"] == "RUNTIME_UNAVAILABLE"
    assert result["reason"] == "nuclei_runtime_unavailable"
    assert result["findings"] == []
    assert result["total_found"] == 0
    assert "no scan was executed" in result["note"]
    assert "simulat" not in str(result).lower()


@pytest.mark.asyncio
async def test_nuclei_runner_blocks_target_guard_violations_before_availability_check(monkeypatch):
    called = {"availability": False}

    def is_available():
        called["availability"] = True
        return False

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(is_available))

    with pytest.raises(TargetGuardError, match="metadata"):
        await NucleiRunner.run_scan("http://169.254.169.254/latest/meta-data")

    assert called["availability"] is False


@pytest.mark.asyncio
async def test_nuclei_runner_rejects_invalid_selectors_before_availability_check(monkeypatch):
    called = {"availability": False}

    def is_available():
        called["availability"] = True
        return False

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(is_available))

    with pytest.raises(ValueError, match="template_ids"):
        await NucleiRunner.run_scan(
            "https://api.example.com",
            template_ids=["../../escape"],
        )

    assert called["availability"] is False


@pytest.mark.asyncio
async def test_nuclei_runner_applies_configured_timeout_and_rate_limit(monkeypatch):
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        return FakeProcess()

    async def fake_wait_for(awaitable, timeout):
        captured["wait_timeout"] = timeout
        return await awaitable

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr("sentinel_worker.modules.nuclei.runner.settings.NUCLEI_TIMEOUT", 17)
    monkeypatch.setattr("sentinel_worker.modules.nuclei.runner.settings.NUCLEI_RATE_LIMIT", 23)
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr("sentinel_worker.modules.nuclei.runner.asyncio.wait_for", fake_wait_for)

    result = await NucleiRunner.run_scan("https://api.example.com")

    assert result["status"] == "COMPLETED"
    assert captured["args"][captured["args"].index("-timeout") + 1] == "17"
    assert captured["args"][captured["args"].index("-rl") + 1] == "23"
    assert captured["wait_timeout"] == 47


@pytest.mark.asyncio
async def test_nuclei_runner_uses_worker_isolation_sandbox_for_subprocess_cwd(tmp_path, monkeypatch):
    sandbox = tmp_path / "workers" / "nuclei-sandbox"
    sandbox.mkdir(parents=True)
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["cwd"] = kwargs["cwd"]
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        timeout=5,
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
async def test_nuclei_runner_uses_secret_file_without_shell_and_excludes_dast(monkeypatch):
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (
                b'{"template-id":"exposed-admin","matched-at":"https://api.example.com/admin"}\n',
                b"",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["cwd"] = kwargs["cwd"]
        secret_path = args[args.index("-sf") + 1]
        with open(secret_path, encoding="utf-8") as secret_file:
            captured["secret_file_content"] = secret_file.read()
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        template_ids=["exposed-admin"],
        tags=["exposure"],
        severity=["high"],
        secret_file_content="static:\n- type: bearertoken\n  token: raw-token-123\n",
        timeout=5,
    )

    assert result["status"] == "COMPLETED"
    assert result["total_found"] == 1
    assert captured["args"][1:3] == ("-target", "https://api.example.com")
    assert "-sf" in captured["args"]
    assert "-exclude-tags" in captured["args"]
    assert "dast" in captured["args"]
    assert captured["secret_file_content"].endswith("token: raw-token-123\n")
    assert captured["cwd"]


@pytest.mark.asyncio
async def test_nuclei_runner_ignores_blank_secret_file_content(monkeypatch):
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["cwd"] = kwargs["cwd"]
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        secret_file_content=" \n\t",
        timeout=5,
    )

    assert result["status"] == "COMPLETED"
    assert result["auth_secret_file_used"] is False
    assert "-sf" not in captured["args"]
    assert captured["cwd"]


@pytest.mark.asyncio
async def test_nuclei_runner_normalizes_selector_inputs_before_cli(monkeypatch):
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        template_ids=["exposed-admin", "exposed-admin"],
        tags=["Exposure", "exposure"],
        severity=["HIGH"],
    )

    assert result["status"] == "COMPLETED"
    assert captured["args"][captured["args"].index("-id") + 1] == "exposed-admin"
    assert captured["args"][captured["args"].index("-tags") + 1] == "exposure"
    assert captured["args"][captured["args"].index("-severity") + 1] == "high"


@pytest.mark.asyncio
async def test_nuclei_runner_allows_dast_only_when_requested(monkeypatch):
    captured = {}

    class FakeProcess:
        async def communicate(self):
            return (b"", b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        tags=["dast"],
        include_dast=True,
    )

    assert result["status"] == "COMPLETED"
    assert result["dast_included"] is True
    assert "-exclude-tags" not in captured["args"]


@pytest.mark.asyncio
async def test_nuclei_runner_reports_nonzero_exit_with_findings_and_redacted_output(monkeypatch):
    class FakeProcess:
        returncode = 2

        async def communicate(self):
            return (
                b'{"template-id":"debug","matched-at":"https://api.example.com/debug?token=raw-token"}\n',
                b"failed with token: raw-token-123",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        secret_file_content="static:\n- type: bearertoken\n  token: raw-token-123\n",
        timeout=5,
    )

    assert result["status"] == "FAILED_WITH_FINDINGS"
    assert result["exit_code"] == 2
    assert result["total_found"] == 1
    assert "nuclei -target" in result["command"]
    assert "raw-token-123" not in str(result)
    assert "token=****" in str(result)


@pytest.mark.asyncio
async def test_nuclei_runner_redacts_finding_urls_and_evidence(monkeypatch):
    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return (
                b'{"template-id":"debug","matched-at":"https://api.example.com/debug?token=raw-query-token","evidence":"Authorization: Bearer raw-token-123"}\n',
                b"",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        secret_file_content="static:\n- type: bearertoken\n  token: raw-token-123\n",
        timeout=5,
    )

    assert result["status"] == "COMPLETED"
    assert result["findings"][0]["matched-at"] == "https://api.example.com/debug?token=****"
    assert result["findings"][0]["evidence"] == "Authorization: Bearer ****"
    assert "raw-query-token" not in str(result)
    assert "raw-token-123" not in str(result)


@pytest.mark.asyncio
async def test_nuclei_runner_kills_process_on_timeout(monkeypatch):
    killed = {"value": False}

    class FakeProcess:
        returncode = None

        def kill(self):
            killed["value"] = True

        async def communicate(self):
            return (b"", b"token: raw-timeout-token")

    async def fake_wait_for(awaitable, timeout):
        raise TimeoutError()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        "sentinel_worker.modules.nuclei.runner.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr("sentinel_worker.modules.nuclei.runner.asyncio.wait_for", fake_wait_for)

    result = await NucleiRunner.run_scan(
        "https://api.example.com",
        secret_file_content="static:\n- type: bearertoken\n  token: raw-timeout-token\n",
        timeout=5,
    )

    assert killed["value"] is True
    assert result["status"] == "TIMEOUT"
    assert result["exit_code"] is None
    assert "raw-timeout-token" not in str(result)
