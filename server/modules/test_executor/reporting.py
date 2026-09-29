import json
import datetime
import hashlib
from typing import Any, List
from xml.etree.ElementTree import Element, SubElement, tostring

from server.models.core import TestRun, TestResult
from server.modules.pentest.engine_plan import ENGINE_EXECUTION_ORDER, engine_outcome_summaries
from server.modules.pentest.execution_artifacts import (
    artifact_content_governance_summary,
    verify_execution_artifact_payload,
)
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    verify_vulnerability_evidence,
)

_ENGINE_EXECUTION_ARTIFACT_TYPES = {
    "templates": "templates_execution",
    "schemathesis": "schemathesis_execution",
    "nuclei": "nuclei_execution",
    "zap": "zap_execution",
    "passive": "passive_findings",
}
_SELECTION_SUMMARY_COUNT_KEYS = (
    "selected_pair_count",
    "skipped_pair_count",
    "pair_decision_count",
)
_COVERAGE_TARGET_KEYS = ("authorization", "business_logic", "llm_api")
_COVERAGE_BOOL_KEYS = ("template_requested", "template_covered")
_IDENTITY_CONTEXT_KEYS = (
    "role_count",
    "multi_identity_ready",
    "privileged_role_present",
    "low_privilege_role_present",
    "privilege_boundary_pair_count",
)
_ACTIVE_TEST_FAMILIES = (
    "coupon_abuse",
    "otp_spam",
    "workflow_bypass",
    "monetary_abuse",
    "resource_exhaustion",
    "prompt_injection",
    "rag_exfiltration",
    "indirect_prompt_injection",
    "dangerous_tool_invocation",
    "privilege_escalating_tool_invocation",
    "tool_chain_injection",
)
_ACTIVE_FAMILY_KEYS = (
    "template_count",
    "endpoint_signal_count",
    "ready",
    "status",
    "signals",
)
_EXTERNAL_WORKER_ISOLATION_MODES = {"leased_external_worker", "kubernetes_job"}
_WORKER_ISOLATION_MODE_ALIASES = {
    "queued": "leased_external_worker",
    "external_worker": "leased_external_worker",
    "leased_external_worker": "leased_external_worker",
    "k8s": "kubernetes_job",
    "k8s_job": "kubernetes_job",
    "kubernetes": "kubernetes_job",
    "kubernetes_job": "kubernetes_job",
}
_WORKER_ISOLATION_RESOURCE_LIMIT_KEYS = ("cpu", "memory", "ephemeral_storage")
_WORKER_ISOLATION_SESSION_FIELDS = (
    "run_id",
    "worker_id",
    "engine",
    "mode",
    "sandbox_id",
    "created_at",
)
_WORKER_ISOLATION_ENFORCEMENT_FIELDS = (
    "runtime_context_created",
    "filesystem_workdir_enforced",
    "subprocess_cwd_confined",
)


def _safe_text(value) -> str:
    if value is None:
        return ""
    return Redactor.redact_text(str(value))


def _evidence_payload(result: TestResult):
    evidence = result.evidence
    if isinstance(evidence, str):
        try:
            return json.loads(evidence)
        except (TypeError, ValueError):
            return evidence
    return evidence


def _evidence_hash(result: TestResult) -> str | None:
    evidence = _evidence_payload(result)
    if isinstance(evidence, dict):
        value = evidence.get("evidence_hash")
        return str(value) if value else None
    return None


def _evidence_integrity_summary(result: TestResult) -> dict[str, object]:
    integrity = verify_vulnerability_evidence(_evidence_payload(result))
    finding = integrity.get("finding_evidence") if isinstance(integrity.get("finding_evidence"), dict) else {}
    return {
        "verified": integrity.get("verified") is True,
        "checked_count": integrity.get("checked_count", 0),
        "failed_count": integrity.get("failed_count", 0),
        "missing_count": integrity.get("missing_count", 0),
        "finding_status": finding.get("status"),
    }


def _safety_policy_metadata(result: TestResult) -> dict[str, object]:
    evidence = _evidence_payload(result)
    if not isinstance(evidence, dict):
        return {}

    policies = evidence.get("safety_policies")
    if not isinstance(policies, dict):
        return {}

    redacted = Redactor.redact_scan_result({"safety_policies": policies})
    safe_policies = redacted.get("safety_policies")
    return safe_policies if isinstance(safe_policies, dict) else {}


def _result_payload(result: TestResult) -> dict:
    payload = {
        "endpoint_id": result.endpoint_id,
        "template_id": result.template_id,
        "severity": result.severity,
        "evidence": _safe_text(result.evidence),
        "evidence_hash": _evidence_hash(result),
        "evidence_integrity": _evidence_integrity_summary(result),
        "confirmation_status": confirmation_status_from_evidence(_evidence_payload(result)),
        "error": _safe_text(result.error),
        "skip_reason": result.skip_reason,
    }
    safety_policies = _safety_policy_metadata(result)
    if safety_policies:
        payload["safety_policies"] = safety_policies
    return payload


def _sarif_result(result: TestResult) -> dict:
    level = "warning"
    if (result.severity or "").upper() in {"CRITICAL", "HIGH"}:
        level = "error"
    elif (result.severity or "").upper() == "LOW":
        level = "note"
    properties = {
        "endpoint_id": result.endpoint_id,
        "severity": result.severity,
        "evidence": _safe_text(result.evidence),
        "evidence_hash": _evidence_hash(result),
        "evidence_integrity": _evidence_integrity_summary(result),
        "confirmation_status": confirmation_status_from_evidence(_evidence_payload(result)),
        "skip_reason": result.skip_reason,
    }
    safety_policies = _safety_policy_metadata(result)
    if safety_policies:
        properties["safety_policies"] = safety_policies
    return {
        "ruleId": result.template_id or "unknown-template",
        "level": level,
        "message": {"text": f"{result.template_id} on {result.endpoint_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": result.endpoint_id or "unknown-endpoint"},
                }
            }
        ],
        "properties": properties,
    }


def _report_counts(results: List[TestResult]) -> dict[str, int]:
    return {
        "total_results": len(results),
        "vulnerable_results": sum(1 for r in results if r.is_vulnerable),
        "errored_results": sum(1 for r in results if r.error),
        "skipped_results": sum(1 for r in results if r.skip_reason),
        "executed_results": sum(1 for r in results if not r.skip_reason),
    }


def _safety_policy_summary(results: List[TestResult]) -> dict[str, object] | None:
    policy_counts: dict[str, int] = {}
    results_with_policies = 0
    for result in results:
        policies = _safety_policy_metadata(result)
        if not policies:
            continue
        results_with_policies += 1
        for key, policy in policies.items():
            if isinstance(policy, dict):
                policy_counts[str(key)] = policy_counts.get(str(key), 0) + 1

    if not policy_counts:
        return None
    return {
        "results_with_safety_policies": results_with_policies,
        "policy_keys": sorted(policy_counts),
        "policy_counts": {key: policy_counts[key] for key in sorted(policy_counts)},
    }


def _skipped_result_details(results: List[TestResult]) -> list[dict[str, object]]:
    details = []
    for result in results:
        if not result.skip_reason:
            continue
        detail = {
            "endpoint_id": result.endpoint_id,
            "template_id": result.template_id,
            "severity": result.severity,
            "skip_reason": result.skip_reason,
            "evidence_hash": _evidence_hash(result),
        }
        safety_policies = _safety_policy_metadata(result)
        if safety_policies:
            detail["safety_policies"] = safety_policies
        details.append(detail)
    return details


def _canonical_sarif_payload(payload: dict) -> dict:
    canonical = json.loads(json.dumps(payload, sort_keys=True, default=str))
    for run in canonical.get("runs", []):
        if not isinstance(run, dict):
            continue
        for invocation in run.get("invocations", []):
            if isinstance(invocation, dict):
                invocation.pop("endTimeUtc", None)
    return canonical


def _json_sha256(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _normalized_worker_isolation_mode(isolation: dict[str, object]) -> str:
    session = isolation.get("session") if isinstance(isolation.get("session"), dict) else {}
    raw_mode = str(
        session.get("mode")
        or isolation.get("configured_worker_isolation_mode")
        or isolation.get("isolation_mode")
        or ""
    ).strip().lower()
    return _WORKER_ISOLATION_MODE_ALIASES.get(raw_mode, raw_mode)


def _worker_isolation_accountability(content: dict[str, object] | None) -> dict[str, object]:
    isolation = content.get("worker_isolation") if isinstance(content, dict) else None
    isolation = isolation if isinstance(isolation, dict) else {}
    mode = _normalized_worker_isolation_mode(isolation)
    if mode not in _EXTERNAL_WORKER_ISOLATION_MODES:
        return {
            "required": False,
            "complete": True,
            "status": "not_required",
            "mode": Redactor.redact_text(mode or "background"),
            "missing_fields": [],
        }

    missing_fields: list[str] = []
    session = isolation.get("session") if isinstance(isolation.get("session"), dict) else None
    sandbox = isolation.get("sandbox") if isinstance(isolation.get("sandbox"), dict) else {}
    manifest = isolation.get("manifest") if isinstance(isolation.get("manifest"), dict) else {}
    resource_limits = (
        isolation.get("resource_limits")
        if isinstance(isolation.get("resource_limits"), dict)
        else {}
    )
    kubernetes_job = (
        isolation.get("kubernetes_job")
        if isinstance(isolation.get("kubernetes_job"), dict)
        else {}
    )
    enforcement = isolation.get("enforcement") if isinstance(isolation.get("enforcement"), dict) else {}

    if not isinstance(session, dict):
        missing_fields.append("session")
    else:
        for field in _WORKER_ISOLATION_SESSION_FIELDS:
            if not str(session.get(field) or "").strip():
                missing_fields.append(f"session.{field}")
    if sandbox.get("created") is not True:
        missing_fields.append("sandbox.created")
    if sandbox.get("path_confined_to_work_dir") is not True:
        missing_fields.append("sandbox.path_confined_to_work_dir")
    if not _is_sha256(manifest.get("sha256")):
        missing_fields.append("manifest.sha256")
    for field in _WORKER_ISOLATION_RESOURCE_LIMIT_KEYS:
        if not str(resource_limits.get(field) or "").strip():
            missing_fields.append(f"resource_limits.{field}")
    if mode == "kubernetes_job" and kubernetes_job.get("enabled") is not True:
        missing_fields.append("kubernetes_job.enabled")
    for field in _WORKER_ISOLATION_ENFORCEMENT_FIELDS:
        if enforcement.get(field) is not True:
            missing_fields.append(f"enforcement.{field}")
    if isolation.get("secret_values_persisted") is not False:
        missing_fields.append("secret_values_persisted")

    return {
        "required": True,
        "complete": not missing_fields,
        "status": "complete" if not missing_fields else "incomplete",
        "mode": Redactor.redact_text(mode),
        "missing_fields": _safe_signal_list(missing_fields, limit=120),
    }


def _run_engine_plan(run: TestRun) -> list[dict[str, object]]:
    scan_plan = getattr(run, "scan_plan", None)
    if not isinstance(scan_plan, dict):
        return []
    engine_plan = scan_plan.get("engine_plan")
    if not isinstance(engine_plan, list):
        return []
    redacted = Redactor.redact_json(engine_plan)
    if not isinstance(redacted, list):
        return []
    return [item for item in redacted if isinstance(item, dict)]


def _artifact_type(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("artifact_type") or "")
    return str(getattr(value, "artifact_type", "") or "")


def _artifact_content_json(value: object) -> dict[str, object] | None:
    content = value.get("content_json") if isinstance(value, dict) else getattr(value, "content_json", None)
    return content if isinstance(content, dict) else None


def _content_artifact_hash(content: dict[str, object] | None) -> str | None:
    if not isinstance(content, dict):
        return None
    artifact_hash = content.get("artifact_hash")
    return Redactor.redact_text(str(artifact_hash)) if artifact_hash else None


def _execution_artifact_index(execution_artifacts: list[object] | None) -> dict[str, dict[str, object]]:
    indexed: dict[str, dict[str, object]] = {}
    for artifact in execution_artifacts or []:
        artifact_type = _artifact_type(artifact)
        if not artifact_type:
            continue
        content = _artifact_content_json(artifact)
        artifact_hash = _content_artifact_hash(content)
        if artifact_type in indexed:
            indexed_artifact = indexed[artifact_type]
            duplicate_count = _safe_int(indexed_artifact.get("artifact_count")) + 1
            indexed_artifact["artifact_count"] = duplicate_count
            duplicate_hashes = indexed_artifact.setdefault("artifact_hashes", [])
            if not isinstance(duplicate_hashes, list):
                duplicate_hashes = []
                indexed_artifact["artifact_hashes"] = duplicate_hashes
            existing_hash = _content_artifact_hash(indexed_artifact.get("content_json"))
            if existing_hash and not duplicate_hashes:
                duplicate_hashes.append(existing_hash)
            if artifact_hash:
                duplicate_hashes.append(artifact_hash)
            continue
        indexed[artifact_type] = {
            "artifact_type": artifact_type,
            "content_json": content,
            "artifact_count": 1,
            "artifact_hashes": [artifact_hash] if artifact_hash else [],
        }
    return indexed


def _artifact_verification_summary(
    content: dict[str, object] | None,
    *,
    expected_engine: str | None = None,
    expected_run_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(content, dict):
        return {
            "verified": False,
            "status": "missing",
            "hash_algorithm": "sha256",
            "artifact_hash": None,
            "expected_hash": None,
            "actual_hash": None,
        }
    verification = verify_execution_artifact_payload(content)
    verified = verification.get("verified") is True
    artifact_hash = content.get("artifact_hash")
    summary: dict[str, object] = {
        "verified": verified,
        "status": "verified" if verified else "unverified",
        "hash_algorithm": verification.get("hash_algorithm") or content.get("hash_algorithm"),
        "artifact_hash": Redactor.redact_text(str(artifact_hash)) if artifact_hash else None,
        "expected_hash": verification.get("expected_hash"),
        "actual_hash": verification.get("actual_hash"),
    }
    if verified and expected_engine is not None:
        artifact_engine = Redactor.redact_text(str(content.get("engine") or ""))
        if artifact_engine != expected_engine:
            summary.update(
                {
                    "verified": False,
                    "status": "engine_mismatch",
                    "expected_engine": expected_engine,
                    "artifact_engine": artifact_engine,
                    "mismatch_fields": ["engine"],
                }
            )
    if summary["verified"] is True and expected_run_id is not None:
        artifact_run_id = Redactor.redact_text(str(content.get("run_id") or ""))
        if artifact_run_id and artifact_run_id != expected_run_id:
            summary.update(
                {
                    "verified": False,
                    "status": "run_mismatch",
                    "expected_run_id": expected_run_id,
                    "artifact_run_id": artifact_run_id,
                    "mismatch_fields": ["run_id"],
                }
            )
    return summary


def _artifact_selection_accountability(content: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(content, dict):
        return None
    selection = content.get("context_aware_selection")
    if not isinstance(selection, dict):
        return None
    redacted = Redactor.redact_scan_result(selection)
    if not isinstance(redacted, dict):
        return None
    redacted.pop("sent_request", None)
    redacted.pop("received_response", None)
    return redacted


def _selection_accountability_detail(
    *,
    engine: str,
    artifact_type: str,
    content: dict[str, object] | None,
    verification: dict[str, object],
    duplicate_count: int = 0,
) -> dict[str, object]:
    present = isinstance(content, dict)
    verified = verification.get("verified") is True
    selection = _artifact_selection_accountability(content if present else None)
    selection_present = isinstance(selection, dict) and selection.get("present") is True
    detail: dict[str, object] = {
        "engine": engine,
        "artifact_type": artifact_type,
        "artifact_present": present,
        "artifact_verified": verified,
        "selection_accountability_present": selection_present,
    }
    if duplicate_count > 1:
        detail.update(
            {
                "status": "duplicate_artifact",
                "duplicate_count": duplicate_count,
            }
        )
        return detail
    if not present:
        detail["status"] = "missing_artifact"
        return detail
    if not selection_present:
        detail["status"] = "missing_selection_accountability"
        return detail
    if not verified:
        detail["status"] = "unverified_artifact"
        return detail

    detail["status"] = "trusted"
    detail["context_status"] = _safe_text(selection.get("status"))
    if selection.get("scan_plan_hash"):
        detail["scan_plan_hash"] = _safe_text(selection.get("scan_plan_hash"))

    selection_summary = selection.get("selection")
    if isinstance(selection_summary, dict):
        for key in _SELECTION_SUMMARY_COUNT_KEYS:
            if key in selection_summary:
                detail[key] = _safe_int(selection_summary.get(key))
        if "pair_decision_report_truncated" in selection_summary:
            detail["pair_decision_report_truncated"] = bool(
                selection_summary.get("pair_decision_report_truncated")
            )

    signals = selection.get("signals")
    if isinstance(signals, dict):
        missing_signals = _safe_signal_list(signals.get("missing"))
        if missing_signals:
            detail["missing_signals"] = missing_signals

    signal_gaps = _safe_context_signal_gaps(selection.get("signal_gaps"))
    if signal_gaps:
        detail["context_signal_gap_count"] = len(signal_gaps)
        detail["context_signal_gaps"] = signal_gaps

    coverage_targets = selection.get("coverage_targets")
    if isinstance(coverage_targets, dict):
        detail["coverage_targets"] = [
            key
            for key in _COVERAGE_TARGET_KEYS
            if isinstance(coverage_targets.get(key), dict)
        ]
        coverage_target_details = _safe_coverage_target_details(coverage_targets)
        if coverage_target_details:
            detail["coverage_target_details"] = coverage_target_details
    return detail


def _selection_accountability_manifest(
    run: TestRun,
    *,
    ready_active_engines: list[str],
    artifact_index: dict[str, dict[str, object]],
) -> dict[str, object]:
    scan_plan = getattr(run, "scan_plan", None)
    context = scan_plan.get("context") if isinstance(scan_plan, dict) and isinstance(scan_plan.get("context"), dict) else {}
    scan_plan_context_present = bool(
        isinstance(scan_plan, dict)
        and (
            isinstance(scan_plan.get("context"), dict)
            or isinstance(scan_plan.get("selection"), dict)
            or isinstance(scan_plan.get("coverage_targets"), dict)
        )
    )
    details: list[dict[str, object]] = []
    trusted_count = 0
    missing_count = 0
    unverified_count = 0
    for engine in ready_active_engines:
        artifact_type = _ENGINE_EXECUTION_ARTIFACT_TYPES[engine]
        artifact = artifact_index.get(artifact_type)
        content = artifact.get("content_json") if isinstance(artifact, dict) else None
        content = content if isinstance(content, dict) else None
        verification = _artifact_verification_summary(
            content,
            expected_engine=engine,
            expected_run_id=Redactor.redact_text(str(run.id or "")),
        )
        detail = _selection_accountability_detail(
            engine=engine,
            artifact_type=artifact_type,
            content=content,
            verification=verification,
            duplicate_count=_safe_int(artifact.get("artifact_count")) if isinstance(artifact, dict) else 0,
        )
        details.append(detail)
        status = detail.get("status")
        if status == "trusted":
            trusted_count += 1
        elif status in {"duplicate_artifact", "unverified_artifact"}:
            unverified_count += 1
        else:
            missing_count += 1

    required = bool(ready_active_engines)
    result: dict[str, object] = {
        "required": required,
        "scan_plan_context_present": scan_plan_context_present,
        "run_context_status": _safe_text(context.get("status") or "unknown"),
        "required_engine_count": len(ready_active_engines),
        "trusted_selection_accountability_count": trusted_count,
        "missing_selection_accountability_count": missing_count,
        "unverified_selection_accountability_count": unverified_count,
        "selection_accountability_complete": required and trusted_count == len(ready_active_engines),
        "engine_details": details,
    }
    if isinstance(scan_plan, dict) and scan_plan.get("scan_plan_hash"):
        result["run_scan_plan_hash"] = _safe_text(scan_plan.get("scan_plan_hash"))
    return result


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_signal_list(value: object, *, limit: int = 120) -> list[str]:
    if not isinstance(value, list):
        return []
    signals: list[str] = []
    for item in value[:50]:
        signal = _safe_text(item)[:limit]
        if signal and signal not in signals:
            signals.append(signal)
    return signals


def _safe_coverage_target_details(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    details: dict[str, object] = {}
    for target_key in _COVERAGE_TARGET_KEYS:
        target = value.get(target_key)
        if not isinstance(target, dict):
            continue
        safe_target: dict[str, object] = {}
        for key in _COVERAGE_BOOL_KEYS:
            if key in target:
                safe_target[key] = bool(target.get(key))
        if "endpoint_signal_count" in target:
            safe_target["endpoint_signal_count"] = _safe_int(target.get("endpoint_signal_count"))
        if target.get("status") is not None:
            safe_target["status"] = _safe_text(target.get("status"))[:80]
        safe_target["signals"] = _safe_signal_list(target.get("signals"))

        identity_context = _safe_identity_context(target.get("identity_context"))
        if identity_context:
            safe_target["identity_context"] = identity_context

        readiness = _safe_bool_mapping(target.get("readiness"))
        if readiness:
            safe_target["readiness"] = readiness

        active_families = _safe_active_test_families(target.get("active_test_families"))
        if active_families:
            safe_target["active_test_families"] = active_families

        details[target_key] = safe_target
    return details


def _safe_identity_context(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for key in _IDENTITY_CONTEXT_KEYS:
        if key not in value:
            continue
        if isinstance(value.get(key), bool):
            result[key] = bool(value.get(key))
        else:
            result[key] = _safe_int(value.get(key))
    return result


def _safe_bool_mapping(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {
        _safe_text(key)[:80]: bool(item)
        for key, item in value.items()
        if isinstance(item, bool)
    }


def _safe_active_test_families(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for family in _ACTIVE_TEST_FAMILIES:
        item = value.get(family)
        if not isinstance(item, dict):
            continue
        safe_item: dict[str, object] = {}
        for key in _ACTIVE_FAMILY_KEYS:
            if key not in item:
                continue
            if key in {"template_count", "endpoint_signal_count"}:
                safe_item[key] = _safe_int(item.get(key))
            elif key == "ready":
                safe_item[key] = bool(item.get(key))
            elif key == "signals":
                safe_item[key] = _safe_signal_list(item.get(key))
            else:
                safe_item[key] = _safe_text(item.get(key))[:80]
        result[family] = safe_item
    return result


def _safe_context_signal_gaps(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    gaps: list[dict[str, object]] = []
    for item in value[:25]:
        if not isinstance(item, dict):
            continue
        gaps.append(
            {
                "signal": _safe_text(item.get("signal"))[:80],
                "required_template_count": _safe_int(item.get("required_template_count")),
                "available_context_count": _safe_int(item.get("available_context_count")),
                "affected_template_count": _safe_int(item.get("affected_template_count")),
                "affected_template_ids": _safe_signal_list(item.get("affected_template_ids"))[:25],
                "recommended_inputs": _safe_signal_list(
                    item.get("recommended_inputs"),
                    limit=160,
                )[:5],
            }
        )
    return gaps


def _engine_artifact_accountability_detail(
    *,
    engine: str,
    artifact_type: str,
    artifact_index: dict[str, dict[str, object]],
    expected_run_id: str | None,
) -> dict[str, object]:
    artifact = artifact_index.get(artifact_type)
    content = artifact.get("content_json") if isinstance(artifact, dict) else None
    content = content if isinstance(content, dict) else None
    verification = _artifact_verification_summary(
        content,
        expected_engine=engine,
        expected_run_id=expected_run_id,
    )
    present = isinstance(content, dict)
    detail: dict[str, object] = {
        "engine": engine,
        "artifact_type": artifact_type,
        "present": present,
        "verified": verification["verified"],
        "status": verification["status"],
        "hash_algorithm": verification["hash_algorithm"] or "sha256",
    }
    if present:
        detail.update(
            {
                "artifact_hash": verification["artifact_hash"],
                "expected_hash": verification["expected_hash"],
                "actual_hash": verification["actual_hash"],
            }
        )
        if verification.get("status") == "engine_mismatch":
            detail.update(
                {
                    "expected_engine": verification.get("expected_engine"),
                    "artifact_engine": verification.get("artifact_engine"),
                    "mismatch_fields": verification.get("mismatch_fields"),
                }
            )
        if verification.get("status") == "run_mismatch":
            detail.update(
                {
                    "expected_run_id": verification.get("expected_run_id"),
                    "artifact_run_id": verification.get("artifact_run_id"),
                    "mismatch_fields": verification.get("mismatch_fields"),
                }
            )
        duplicate_count = _safe_int(artifact.get("artifact_count")) if isinstance(artifact, dict) else 0
        if duplicate_count > 1:
            artifact_hashes = artifact.get("artifact_hashes") if isinstance(artifact, dict) else []
            detail.update(
                {
                    "verified": False,
                    "status": "duplicate_artifact",
                    "duplicate_count": duplicate_count,
                    "duplicate_artifact_hashes": _safe_signal_list(artifact_hashes, limit=128),
                }
            )
        elif detail.get("status") == "verified":
            content_governance = artifact_content_governance_summary(content, expected_engine=engine)
            if content_governance.get("complete") is not True:
                detail.update(
                    {
                        "verified": False,
                        "status": "artifact_content_governance_failed",
                        "artifact_content_governance": content_governance,
                    }
                )
            else:
                worker_isolation = _worker_isolation_accountability(content)
                if worker_isolation.get("required") is True and worker_isolation.get("complete") is not True:
                    detail.update(
                        {
                            "verified": False,
                            "status": "worker_isolation_incomplete",
                            "worker_isolation": worker_isolation,
                        }
                    )
    return detail


def _engine_accountability_manifest(
    run: TestRun,
    *,
    execution_artifacts: list[object] | None = None,
) -> dict[str, object]:
    engine_plan = _run_engine_plan(run)
    engine_plan_present = bool(engine_plan)
    entries = {
        str(item.get("engine")): item
        for item in engine_plan
        if str(item.get("engine")) in ENGINE_EXECUTION_ORDER
    }
    ready_active_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if engine != "passive" and entries.get(engine, {}).get("status") == "ready"
    ]
    blocked_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "blocked"
    ]
    disabled_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") == "disabled"
    ]
    continuous_engines = [
        engine
        for engine in ENGINE_EXECUTION_ORDER
        if entries.get(engine, {}).get("status") in {"available", "continuous"}
    ]
    artifact_index = _execution_artifact_index(execution_artifacts)
    expected_run_id = Redactor.redact_text(str(run.id or ""))
    required_artifacts: list[dict[str, object]] = []
    missing_count = 0
    unverified_count = 0
    duplicate_count = 0
    incomplete_worker_isolation_count = 0
    content_governance_failed_count = 0
    for engine in ready_active_engines:
        artifact_type = _ENGINE_EXECUTION_ARTIFACT_TYPES[engine]
        detail = _engine_artifact_accountability_detail(
            engine=engine,
            artifact_type=artifact_type,
            artifact_index=artifact_index,
            expected_run_id=expected_run_id,
        )
        if detail["present"] is not True:
            missing_count += 1
        elif detail["verified"] is not True:
            unverified_count += 1
        if detail.get("status") == "duplicate_artifact":
            duplicate_count += 1
        if detail.get("status") == "worker_isolation_incomplete":
            incomplete_worker_isolation_count += 1
        if detail.get("status") == "artifact_content_governance_failed":
            content_governance_failed_count += 1
        required_artifacts.append(detail)

    continuous_artifacts: list[dict[str, object]] = []
    missing_continuous_count = 0
    unverified_continuous_count = 0
    duplicate_continuous_count = 0
    incomplete_continuous_worker_isolation_count = 0
    content_governance_failed_continuous_count = 0
    for engine in continuous_engines:
        artifact_type = _ENGINE_EXECUTION_ARTIFACT_TYPES[engine]
        detail = _engine_artifact_accountability_detail(
            engine=engine,
            artifact_type=artifact_type,
            artifact_index=artifact_index,
            expected_run_id=expected_run_id,
        )
        if detail["present"] is not True:
            missing_continuous_count += 1
        elif detail["verified"] is not True:
            unverified_continuous_count += 1
        if detail.get("status") == "duplicate_artifact":
            duplicate_continuous_count += 1
        if detail.get("status") == "worker_isolation_incomplete":
            incomplete_continuous_worker_isolation_count += 1
        if detail.get("status") == "artifact_content_governance_failed":
            content_governance_failed_continuous_count += 1
        continuous_artifacts.append(detail)

    return {
        "required": engine_plan_present,
        "complete": (
            engine_plan_present
            and missing_count == 0
            and unverified_count == 0
            and duplicate_count == 0
        ),
        "scan_plan_engine_plan_present": engine_plan_present,
        "execution_order": list(ENGINE_EXECUTION_ORDER),
        "ready_active_engines": ready_active_engines,
        "continuous_engines": continuous_engines,
        "blocked_engines": blocked_engines,
        "disabled_engines": disabled_engines,
        "ready_engine_count": len(ready_active_engines),
        "blocked_engine_count": len(blocked_engines),
        "disabled_engine_count": len(disabled_engines),
        "required_artifacts": required_artifacts,
        "missing_artifact_count": missing_count,
        "unverified_artifact_count": unverified_count,
        "duplicate_artifact_count": duplicate_count,
        "incomplete_worker_isolation_artifact_count": incomplete_worker_isolation_count,
        "content_governance_failed_artifact_count": content_governance_failed_count,
        "continuous_artifacts": continuous_artifacts,
        "continuous_artifact_count": len(continuous_artifacts),
        "missing_continuous_artifact_count": missing_continuous_count,
        "unverified_continuous_artifact_count": unverified_continuous_count,
        "duplicate_continuous_artifact_count": duplicate_continuous_count,
        "incomplete_continuous_worker_isolation_artifact_count": (
            incomplete_continuous_worker_isolation_count
        ),
        "content_governance_failed_continuous_artifact_count": (
            content_governance_failed_continuous_count
        ),
        "continuous_artifact_accountability_complete": (
            not continuous_engines
            or (
                missing_continuous_count == 0
                and unverified_continuous_count == 0
                and duplicate_continuous_count == 0
                and incomplete_continuous_worker_isolation_count == 0
                and content_governance_failed_continuous_count == 0
            )
        ),
        "engine_outcomes": engine_outcome_summaries(engine_plan),
        "selection_accountability": _selection_accountability_manifest(
            run,
            ready_active_engines=ready_active_engines,
            artifact_index=artifact_index,
        ),
    }


def build_sarif(run: TestRun, results: List[TestResult]) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    counts = _report_counts(results)
    sarif_results = [_sarif_result(r) for r in results if r.is_vulnerable]
    invocation_properties = {
        "run_id": run.id,
        "run_status": run.status,
        **counts,
    }
    safety_policy_summary = _safety_policy_summary(results)
    if safety_policy_summary:
        invocation_properties["safety_policy_summary"] = safety_policy_summary
    skipped_details = _skipped_result_details(results)
    if skipped_details:
        invocation_properties["skipped_result_details"] = skipped_details
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "API-Sentinel",
                        "version": "1.0",
                        "informationUri": "https://api-sentinel.local",
                        "rules": [
                            {"id": r.template_id or "unknown-template"}
                            for r in results
                            if r.template_id
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now,
                        "properties": invocation_properties,
                    }
                ],
                "results": sarif_results,
            }
        ],
    }


def build_report_artifact_manifest(
    run: TestRun,
    results: List[TestResult],
    *,
    gate_base_path: str = "/api/cicd/gate",
    execution_artifacts: list[object] | None = None,
) -> dict[str, object]:
    """Return hashes and download locations for CI evidence report artifacts."""
    run_id = run.id or "unknown-run"
    sarif = build_sarif(run, results)
    junit = build_junit(run, results)
    return {
        "required": True,
        "run_id": run.id,
        "result_count": len(results),
        "engine_accountability": _engine_accountability_manifest(
            run,
            execution_artifacts=execution_artifacts,
        ),
        "artifacts": [
            {
                "format": "sarif",
                "name": f"api-sentinel-run-{run_id}.sarif.json",
                "url": f"{gate_base_path}/{run_id}/sarif",
                "media_type": "application/json",
                "hash_algorithm": "sha256",
                "canonicalization": "sarif-drop-invocation-endTimeUtc",
                "canonical_hash": _json_sha256(_canonical_sarif_payload(sarif)),
            },
            {
                "format": "junit",
                "name": f"api-sentinel-run-{run_id}.junit.xml",
                "url": f"{gate_base_path}/{run_id}/junit",
                "media_type": "application/xml",
                "hash_algorithm": "sha256",
                "canonicalization": "raw-xml",
                "canonical_hash": _text_sha256(junit),
            },
        ],
    }


def build_junit(run: TestRun, results: List[TestResult]) -> str:
    suite = Element("testsuite")
    suite.set("name", f"api-sentinel-run-{run.id}")
    suite.set("tests", str(len(results)))
    suite.set("failures", str(sum(1 for r in results if r.is_vulnerable)))
    suite.set("errors", str(sum(1 for r in results if r.error)))
    suite.set("skipped", str(sum(1 for r in results if r.skip_reason)))

    safety_policy_summary = _safety_policy_summary(results)
    if safety_policy_summary:
        properties = SubElement(suite, "properties")
        policy_property = SubElement(properties, "property")
        policy_property.set("name", "api_sentinel.safety_policy_summary")
        policy_property.set(
            "value",
            json.dumps(safety_policy_summary, sort_keys=True, separators=(",", ":")),
        )

    for result in results:
        case = SubElement(suite, "testcase")
        case.set("name", result.template_id or "unknown-template")
        case.set("classname", result.endpoint_id or "unknown-endpoint")
        if result.skip_reason:
            skipped = SubElement(case, "skipped")
            skipped.set("message", result.skip_reason)
            skipped.text = json.dumps(_result_payload(result))
            continue
        if result.error:
            error = SubElement(case, "error")
            error.set("message", _safe_text(result.error))
            error.text = json.dumps(_result_payload(result))
            continue
        if result.is_vulnerable:
            failure = SubElement(case, "failure")
            failure.set("message", result.severity or "HIGH")
            failure.text = json.dumps(_result_payload(result))

    return tostring(suite, encoding="unicode")
