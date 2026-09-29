from __future__ import annotations

import re
from typing import Any

from server.config import settings
from server.modules.pentest.engine_plan import SUCCESSFUL_ENGINE_EXECUTION_STATUSES
from server.modules.pentest.execution_artifacts import verify_execution_artifact_payload
from server.modules.pentest.worker_isolation import (
    configured_scan_execution_mode,
    configured_worker_isolation_mode,
    worker_kubernetes_job_ttl_seconds,
    worker_kubernetes_namespace,
    worker_kubernetes_service_account,
    worker_resource_limits,
)
from server.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from server.modules.utils.redactor import Redactor

_EXTERNAL_ISOLATION_MODES = {"leased_external_worker", "kubernetes_job"}
_HEX_64_RE = re.compile(r"^[a-f0-9]{64}$")


def build_worker_runtime_validation(queue_health: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an operator-facing readiness report for queued isolated scan workers."""
    queue_health = queue_health if isinstance(queue_health, dict) else {}
    execution_mode = _scan_execution_mode()
    isolation_mode = configured_worker_isolation_mode()
    resource_limits = worker_resource_limits()
    lease_seconds = _positive_int(getattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 900), default=900)
    max_claims = _positive_int(getattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 3), default=3)
    kill_switch_paused = kill_switch_enabled()

    checks: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, str]] = []

    checks["queued_workers"] = _check(
        ready=execution_mode == "queued",
        status="ready" if execution_mode == "queued" else "blocked",
        evidence={"execution_mode": execution_mode},
    )
    if not checks["queued_workers"]["ready"]:
        blockers.append(
            _blocker(
                "queued_workers_not_enabled",
                "PENTEST_SCAN_EXECUTION_MODE must be queued for external worker staging scans.",
            )
        )

    checks["external_worker_mode"] = _check(
        ready=isolation_mode in _EXTERNAL_ISOLATION_MODES,
        status="ready" if isolation_mode in _EXTERNAL_ISOLATION_MODES else "blocked",
        evidence={"isolation_mode": isolation_mode},
    )
    if not checks["external_worker_mode"]["ready"]:
        blockers.append(
            _blocker(
                "external_worker_isolation_not_enabled",
                "PENTEST_SCAN_WORKER_ISOLATION_MODE must enable external_worker or kubernetes_job.",
            )
        )

    checks["kubernetes_job_mode"] = _check(
        ready=isolation_mode == "kubernetes_job",
        status="ready" if isolation_mode == "kubernetes_job" else "not_enabled",
        evidence={
            "isolation_mode": isolation_mode,
            "namespace": worker_kubernetes_namespace(),
            "service_account": worker_kubernetes_service_account(),
            "job_ttl_seconds": worker_kubernetes_job_ttl_seconds(),
        },
    )

    checks["lease_expiry"] = _check(
        ready=lease_seconds > 0 and max_claims > 0,
        status="ready",
        evidence={
            "lease_seconds": lease_seconds,
            "max_claims": max_claims,
            "expired_lease_count": _safe_int(queue_health.get("expired_lease_count")),
            "dead_letter_ready_count": _safe_int(queue_health.get("dead_letter_ready_count")),
        },
    )

    checks["kill_switch"] = _check(
        ready=not kill_switch_paused,
        status="ready" if not kill_switch_paused else "paused",
        evidence={"kill_switch_enforced": True, "kill_switch_paused": kill_switch_paused},
    )
    if kill_switch_paused:
        blockers.append(_blocker("kill_switch_paused", KILL_SWITCH_REASON))

    resource_ready = all(str(resource_limits.get(key) or "").strip() for key in ("cpu", "memory", "ephemeral_storage"))
    checks["resource_limits"] = _check(
        ready=resource_ready,
        status="ready" if resource_ready else "blocked",
        evidence=resource_limits,
    )
    if not resource_ready:
        blockers.append(_blocker("worker_resource_limits_missing", "Worker CPU, memory, and ephemeral storage limits are required."))

    checks["sandbox_cleanup"] = _check(
        ready=True,
        status="required",
        evidence={"sandbox_cleanup_required": True, "post_run_verification": "worker_acceptance"},
    )
    checks["worker_artifact_generation"] = _check(
        ready=True,
        status="required",
        evidence={"artifact_hash_required": True, "artifact_verification_required": True},
    )

    return {
        "ready": not blockers,
        "status": "ready" if not blockers else "blocked",
        "execution_mode": execution_mode,
        "isolation_mode": isolation_mode,
        "checks": checks,
        "blockers": blockers,
    }


def validate_worker_staging_scan_acceptance(
    worker_result: dict[str, Any] | None,
    artifact_payload: dict[str, Any] | None,
    *,
    artifact_payloads: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate a concrete staging worker run emitted cleanup and hashed artifact evidence."""
    worker_result = worker_result if isinstance(worker_result, dict) else {}
    artifact_payload = artifact_payload if isinstance(artifact_payload, dict) else {}
    worker_isolation = worker_result.get("worker_isolation") if isinstance(worker_result.get("worker_isolation"), dict) else {}
    session = worker_isolation.get("session") if isinstance(worker_isolation.get("session"), dict) else {}
    cleanup = worker_isolation.get("cleanup") if isinstance(worker_isolation.get("cleanup"), dict) else {}
    sandbox = worker_isolation.get("sandbox") if isinstance(worker_isolation.get("sandbox"), dict) else {}
    resource_limits = worker_isolation.get("resource_limits") if isinstance(worker_isolation.get("resource_limits"), dict) else {}
    kubernetes_job = worker_isolation.get("kubernetes_job") if isinstance(worker_isolation.get("kubernetes_job"), dict) else {}
    isolation_mode = str(session.get("mode") or worker_isolation.get("configured_worker_isolation_mode") or "")
    artifact_hash = str(artifact_payload.get("artifact_hash") or "")
    verification = _artifact_verification(artifact_payload)

    checks: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, str]] = []

    checks["queued_worker_execution"] = _check(
        ready=bool(worker_result.get("claimed"))
        and str(worker_result.get("status") or "") == "executed"
        and bool(worker_result.get("run_id"))
        and bool(worker_result.get("worker_id")),
        status="ready" if str(worker_result.get("status") or "") == "executed" else "blocked",
        evidence={
            "claimed": bool(worker_result.get("claimed")),
            "status": Redactor.redact_text(str(worker_result.get("status") or "")),
            "run_id": Redactor.redact_text(str(worker_result.get("run_id") or "")),
            "worker_id": Redactor.redact_text(str(worker_result.get("worker_id") or "")),
        },
    )
    if not checks["queued_worker_execution"]["ready"]:
        blockers.append(_blocker("worker_scan_not_executed", "Queued staging scan did not execute through a claimed worker."))

    checks["lease_expiry"] = _check(
        ready=bool(worker_result.get("lease_expires_at")),
        status="ready" if worker_result.get("lease_expires_at") else "blocked",
        evidence={"lease_expires_at": Redactor.redact_text(str(worker_result.get("lease_expires_at") or ""))},
    )
    if not checks["lease_expiry"]["ready"]:
        blockers.append(_blocker("worker_lease_missing", "Worker run did not expose a dispatch lease expiry."))

    paused = str(worker_result.get("reason") or "") == KILL_SWITCH_REASON
    checks["kill_switch"] = _check(
        ready=not paused,
        status="ready" if not paused else "paused",
        evidence={"kill_switch_enforced": True, "kill_switch_paused": paused},
    )
    if paused:
        blockers.append(_blocker("kill_switch_paused", KILL_SWITCH_REASON))

    checks["external_worker_mode"] = _check(
        ready=isolation_mode in _EXTERNAL_ISOLATION_MODES,
        status="ready" if isolation_mode in _EXTERNAL_ISOLATION_MODES else "blocked",
        evidence={"isolation_mode": Redactor.redact_text(isolation_mode)},
    )
    if not checks["external_worker_mode"]["ready"]:
        blockers.append(_blocker("worker_isolation_not_external", "Worker run did not use external worker isolation."))

    kubernetes_ready = isolation_mode != "kubernetes_job" or bool(kubernetes_job.get("enabled"))
    checks["kubernetes_job_mode"] = _check(
        ready=kubernetes_ready,
        status="ready" if isolation_mode == "kubernetes_job" and kubernetes_ready else "not_required",
        evidence={
            "isolation_mode": Redactor.redact_text(isolation_mode),
            "kubernetes_job_enabled": bool(kubernetes_job.get("enabled")),
        },
    )
    if not kubernetes_ready:
        blockers.append(_blocker("kubernetes_job_metadata_missing", "Kubernetes job worker run did not include job metadata."))

    sandbox_cleaned = (
        bool(sandbox.get("created"))
        and bool(cleanup.get("path_confined_to_work_dir"))
        and str(cleanup.get("status") or "") == "removed"
    )
    checks["sandbox_cleanup"] = _check(
        ready=sandbox_cleaned,
        status="ready" if sandbox_cleaned else "blocked",
        evidence={
            "sandbox_created": bool(sandbox.get("created")),
            "cleanup_status": Redactor.redact_text(str(cleanup.get("status") or "")),
            "path_confined_to_work_dir": bool(cleanup.get("path_confined_to_work_dir")),
        },
    )
    if not sandbox_cleaned:
        blockers.append(_blocker("worker_sandbox_not_cleaned", "Worker sandbox was not removed after staging execution."))

    resource_ready = all(str(resource_limits.get(key) or "").strip() for key in ("cpu", "memory", "ephemeral_storage"))
    checks["resource_limits"] = _check(
        ready=resource_ready,
        status="ready" if resource_ready else "blocked",
        evidence={str(key): Redactor.redact_text(str(value)) for key, value in resource_limits.items()},
    )
    if not resource_ready:
        blockers.append(_blocker("worker_resource_limits_missing", "Worker artifact lacks CPU, memory, or storage limits."))

    artifact_ready = (
        bool(artifact_payload)
        and bool(_HEX_64_RE.match(artifact_hash))
        and verification.get("verified") is True
    )
    checks["artifact_generation"] = _check(
        ready=artifact_ready,
        status="ready" if artifact_ready else "blocked",
        evidence={
            "artifact_hash_present": bool(_HEX_64_RE.match(artifact_hash)),
            "hash_algorithm": artifact_payload.get("hash_algorithm"),
            "artifact_verified": verification.get("verified") is True,
            "verification_status": verification.get("status"),
        },
    )
    if not artifact_ready:
        blockers.append(_blocker("worker_artifact_not_verified", "Worker did not emit a verified sha256 execution artifact."))

    required_artifacts = []
    accountability = worker_result.get("engine_accountability")
    if isinstance(accountability, dict):
        required_artifacts = [
            item for item in (accountability.get("required_artifacts") or [])
            if isinstance(item, dict) and item.get("artifact_type")
        ]
    artifact_payloads = artifact_payloads or ([artifact_payload] if artifact_payload else [])
    verified_artifact_types = {
        str(payload.get("engine") or "") + "_execution"
        for payload in artifact_payloads
        if isinstance(payload, dict)
        and payload.get("run_id") == worker_result.get("run_id")
        and str(payload.get("status") or "").upper() in SUCCESSFUL_ENGINE_EXECUTION_STATUSES
        and verify_execution_artifact_payload(payload).get("verified") is True
    }
    missing_engine_artifacts = [
        str(item.get("artifact_type"))
        for item in required_artifacts
        if str(item.get("artifact_type")) not in verified_artifact_types
    ]
    checks["required_engine_artifacts"] = _check(
        ready=not missing_engine_artifacts,
        status="ready" if not missing_engine_artifacts else "blocked",
        evidence={
            "required": [str(item.get("artifact_type")) for item in required_artifacts],
            "verified": sorted(verified_artifact_types),
            "missing": missing_engine_artifacts,
        },
    )
    if missing_engine_artifacts:
        blockers.append(
            _blocker(
                "required_engine_artifact_missing",
                "One or more ready engines did not emit a verified execution artifact.",
            )
        )

    return {
        "ready": not blockers,
        "status": "accepted" if not blockers else "blocked",
        "acceptance": "staging_worker_scan",
        "checks": checks,
        "blockers": blockers,
        "evidence": {
            "run_id": Redactor.redact_text(str(worker_result.get("run_id") or artifact_payload.get("run_id") or "")),
            "worker_id": Redactor.redact_text(str(worker_result.get("worker_id") or "")),
            "isolation_mode": Redactor.redact_text(isolation_mode),
            "cleanup_status": Redactor.redact_text(str(cleanup.get("status") or "")),
            "artifact_hash": artifact_hash if _HEX_64_RE.match(artifact_hash) else None,
            "hash_algorithm": artifact_payload.get("hash_algorithm"),
            "artifact_verified": verification.get("verified") is True,
        },
    }


def _artifact_verification(artifact_payload: dict[str, Any]) -> dict[str, Any]:
    if not artifact_payload:
        return {"verified": False, "status": "MISSING"}
    if "artifact_hash" in artifact_payload and "hash_algorithm" in artifact_payload:
        return verify_execution_artifact_payload(artifact_payload)
    verification = artifact_payload.get("artifact_verification")
    return verification if isinstance(verification, dict) else {"verified": False, "status": "MISSING"}


def _scan_execution_mode() -> str:
    return configured_scan_execution_mode()


def _positive_int(value: Any, *, default: int) -> int:
    try:
        return max(1, int(value or default))
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _check(*, ready: bool, status: str, evidence: dict[str, Any]) -> dict[str, Any]:
    safe_evidence = Redactor.redact_json(evidence)
    return {
        "ready": bool(ready),
        "status": Redactor.redact_text(status),
        "evidence": safe_evidence if isinstance(safe_evidence, dict) else {},
    }


def _blocker(blocker_id: str, message: str) -> dict[str, str]:
    return {
        "id": Redactor.redact_text(blocker_id),
        "message": Redactor.redact_text(message),
    }
