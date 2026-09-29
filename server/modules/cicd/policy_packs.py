from __future__ import annotations

from typing import Any


_PACKS: dict[str, dict[str, Any]] = {
    "strict": {
        "name": "strict",
        "fail_on": "CRITICAL,HIGH",
        "fail_on_errors": True,
        "fail_on_no_execution": True,
        "fail_on_unauthenticated": True,
        "require_evidence_integrity": True,
        "require_evidence_completeness": True,
        "require_safety_policies": True,
        "require_retest_support": True,
        "require_confirmatory_retests": True,
        "require_confirmed_findings": False,
        "require_llm_judge_validation": False,
        "require_authorization_boundary_coverage": True,
        "require_engine_artifact_accountability": True,
        "require_ticketed_blocking_vulnerabilities": True,
    },
    "advisory": {
        "name": "advisory",
        "fail_on": "CRITICAL",
        "fail_on_errors": True,
        "fail_on_no_execution": True,
        "fail_on_unauthenticated": True,
        "require_evidence_integrity": True,
        "require_evidence_completeness": True,
        "require_safety_policies": True,
        "require_retest_support": True,
        "require_confirmatory_retests": False,
        "require_confirmed_findings": False,
        "require_llm_judge_validation": False,
        "require_authorization_boundary_coverage": True,
        "require_engine_artifact_accountability": True,
        "require_ticketed_blocking_vulnerabilities": True,
    },
    "evidence-only": {
        "name": "evidence-only",
        "fail_on": "none",
        "fail_on_errors": True,
        "fail_on_no_execution": True,
        "fail_on_unauthenticated": True,
        "require_evidence_integrity": True,
        "require_evidence_completeness": True,
        "require_safety_policies": True,
        "require_retest_support": True,
        "require_confirmatory_retests": False,
        "require_confirmed_findings": False,
        "require_llm_judge_validation": False,
        "require_authorization_boundary_coverage": True,
        "require_engine_artifact_accountability": True,
        "require_ticketed_blocking_vulnerabilities": True,
    },
    "llm-strict": {
        "name": "llm-strict",
        "fail_on": "CRITICAL,HIGH",
        "fail_on_errors": True,
        "fail_on_no_execution": True,
        "fail_on_unauthenticated": True,
        "require_evidence_integrity": True,
        "require_evidence_completeness": True,
        "require_safety_policies": True,
        "require_retest_support": True,
        "require_confirmatory_retests": True,
        "require_confirmed_findings": False,
        "require_llm_judge_validation": True,
        "require_authorization_boundary_coverage": True,
        "require_engine_artifact_accountability": True,
        "require_ticketed_blocking_vulnerabilities": True,
    },
}


def resolve_policy_pack(name: str | None) -> dict[str, Any]:
    pack_name = str(name or "strict").strip().lower()
    if pack_name not in _PACKS:
        valid = ", ".join(sorted(_PACKS))
        raise ValueError(f"Unknown CI/CD policy pack '{name}'. Valid packs: {valid}")
    return dict(_PACKS[pack_name])


def available_policy_packs() -> list[str]:
    return sorted(_PACKS)
