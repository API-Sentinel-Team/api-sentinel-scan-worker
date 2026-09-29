"""Nuclei vulnerability scanner integration with fail-closed runtime handling."""
import asyncio
import contextlib
import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml

from server.config import settings
from server.modules.nuclei.selectors import normalize_severities, normalize_tags, normalize_template_ids
from server.modules.pentest.target_policy import validate_pentest_target
from server.modules.pentest.worker_isolation import (
    worker_isolation_child_work_root,
    worker_isolation_enforcement_metadata,
    worker_isolation_subprocess_env,
)
from server.modules.utils.redactor import Redactor

logger = logging.getLogger(__name__)
NUCLEI_BIN = shutil.which("nuclei") or "nuclei"
_SECRET_VALUE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "value",
}


class NucleiRunner:
    @staticmethod
    def cli_path() -> str | None:
        return shutil.which("nuclei")

    @staticmethod
    def is_available() -> bool:
        return NucleiRunner.cli_path() is not None

    @staticmethod
    async def run_scan(
        target: str,
        template_ids: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        extra_template_paths: Optional[List[str]] = None,
        secret_file_content: Optional[str] = None,
        include_dast: bool = False,
        timeout: Optional[int] = None,
        worker_isolation_context: Optional[dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        validate_pentest_target(target)
        template_ids = normalize_template_ids(template_ids)
        tags = normalize_tags(tags)
        severity = normalize_severities(severity)
        effective_timeout = _positive_int(timeout, default=_positive_int(getattr(settings, "NUCLEI_TIMEOUT", 120), default=120))
        rate_limit = _positive_int(getattr(settings, "NUCLEI_RATE_LIMIT", 0), default=0)
        isolation_enforcement = worker_isolation_enforcement_metadata(
            worker_isolation_context,
            engine="nuclei",
        )

        if not NucleiRunner.is_available():
            return {
                "status": "RUNTIME_UNAVAILABLE",
                "reason": "nuclei_runtime_unavailable",
                "findings": [],
                "total_found": 0,
                "note": "nuclei binary is not installed; no scan was executed",
                "worker_isolation_enforcement": isolation_enforcement,
            }

        work_dir = worker_isolation_child_work_root(worker_isolation_context, "nuclei")
        if work_dir is None:
            work_dir = Path(getattr(settings, "PENTEST_SCAN_WORK_DIR", ".")) / "nuclei"
        work_dir.mkdir(parents=True, exist_ok=True)
        run_dir: Path | None = work_dir / f"nuclei_run_{uuid.uuid4().hex}"
        run_dir.mkdir(parents=True, exist_ok=False)
        isolation_enforcement = worker_isolation_enforcement_metadata(
            worker_isolation_context,
            engine="nuclei",
            cwd=run_dir,
        )
        secret_file_path: Path | None = None
        if secret_file_content and secret_file_content.strip():
            secret_file_path = run_dir / "nuclei-secret.yaml"
            secret_file_path.write_text(secret_file_content, encoding="utf-8")

        cmd = [NUCLEI_BIN, "-target", target, "-json", "-silent", "-timeout", str(effective_timeout)]
        if rate_limit > 0:
            cmd += ["-rl", str(rate_limit)]
        if secret_file_path is not None:
            cmd += ["-sf", str(secret_file_path)]
        if not include_dast:
            cmd += ["-exclude-tags", "dast"]
        if template_ids:
            cmd += ["-id", ",".join(template_ids)]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if severity:
            cmd += ["-severity", ",".join(severity)]
        for path in (extra_template_paths or []):
            cmd += ["-t", path]

        findings = []
        secret_values = _secret_values_from_secret_file(secret_file_content or "")
        safe_command = _safe_command(cmd)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(run_dir) if run_dir is not None else None,
                env=worker_isolation_subprocess_env(worker_isolation_context),
            )
            communicate = proc.communicate()
            try:
                stdout, stderr = await asyncio.wait_for(communicate, timeout=effective_timeout + 30)
            except TimeoutError:
                if hasattr(communicate, "close"):
                    communicate.close()
                raise
            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(_redact_finding(json.loads(line), secret_values))
                except json.JSONDecodeError:
                    pass
            exit_code = int(getattr(proc, "returncode", 0) or 0)
            if exit_code == 0:
                status = "COMPLETED"
            elif findings:
                status = "FAILED_WITH_FINDINGS"
            else:
                status = "FAILED"
            return {
                "status": status,
                "exit_code": exit_code,
                "command": safe_command,
                "findings": findings,
                "total_found": len(findings),
                "auth_secret_file_used": secret_file_path is not None,
                "dast_included": bool(include_dast),
                "stdout": _redact_output(stdout.decode("utf-8", errors="replace"), secret_values),
                "stderr": _redact_output(stderr.decode("utf-8", errors="replace"), secret_values),
                "worker_isolation_enforcement": isolation_enforcement,
            }
        except asyncio.CancelledError:
            if "proc" in locals():
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.communicate()
            raise
        except TimeoutError:
            with contextlib.suppress(Exception):
                proc.kill()
            stderr = b""
            with contextlib.suppress(Exception):
                _stdout, stderr = await proc.communicate()
            return {
                "status": "TIMEOUT",
                "exit_code": getattr(proc, "returncode", None),
                "command": safe_command,
                "findings": findings,
                "total_found": len(findings),
                "auth_secret_file_used": secret_file_path is not None,
                "dast_included": bool(include_dast),
                "stderr": _redact_output(stderr.decode("utf-8", errors="replace"), secret_values),
                "worker_isolation_enforcement": isolation_enforcement,
            }
        except Exception as e:
            safe_error = Redactor.redact_text(str(e))
            logger.error(f"Nuclei error: {safe_error}")
            return {
                "status": "FAILED",
                "exit_code": None,
                "command": safe_command,
                "findings": [],
                "total_found": 0,
                "error": safe_error,
                "auth_secret_file_used": secret_file_path is not None,
                "dast_included": bool(include_dast),
                "worker_isolation_enforcement": isolation_enforcement,
            }
        finally:
            if run_dir is not None:
                shutil.rmtree(run_dir, ignore_errors=True)

def _safe_command(cmd: list[str]) -> str:
    return " ".join(Redactor.redact_url(str(item)) for item in cmd)


def _positive_int(value: Any, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return parsed


def _redact_output(text: str, secret_values: list[str]) -> str:
    redacted = text
    for value in sorted(set(secret_values), key=len, reverse=True):
        if len(value) >= 3:
            redacted = redacted.replace(value, Redactor.REDACT_VALUE)
    return Redactor.redact_text(redacted)[:12000]


def _redact_finding(value: Any, secret_values: list[str]) -> Any:
    if isinstance(value, dict):
        return {key: _redact_finding(item, secret_values) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_finding(item, secret_values) for item in value]
    if isinstance(value, str):
        return _redact_output(value, secret_values)
    return value


def _secret_values_from_secret_file(content: str) -> list[str]:
    if not content.strip():
        return []
    try:
        parsed = yaml.safe_load(content)
    except Exception:
        return []
    values: list[str] = []
    _collect_secret_values(parsed, values=values)
    return values


def _collect_secret_values(value: Any, *, values: list[str], key: str = "") -> None:
    normalized_key = key.lower().replace("_", "-")
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            _collect_secret_values(item_value, values=values, key=str(item_key))
        return
    if isinstance(value, list):
        for item in value:
            _collect_secret_values(item, values=values, key=key)
        return
    if isinstance(value, str) and (
        normalized_key in _SECRET_VALUE_KEYS or normalized_key.endswith(("-token", "-secret", "-password"))
    ):
        if "{{" not in value and value.strip():
            values.append(value.strip())
