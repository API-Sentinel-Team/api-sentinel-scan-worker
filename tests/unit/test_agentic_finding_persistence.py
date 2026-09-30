"""Tests for promoting detector/chain/agentic findings into Vulnerability payloads."""
from __future__ import annotations

from sentinel_worker.modules.agentic.finding_persistence import build_agentic_vulnerability_data
from sentinel_core.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence

_ENDPOINT = {
    "id": "ep-1",
    "method": "GET",
    "url": "https://api.example.com/users/1",
    "path": "/users/1",
}


def test_detector_finding_builds_evidence_grade_payload():
    finding = {
        "type": "SQLI",
        "endpoint_id": "ep-1",
        "severity": "HIGH",
        "evidence": {
            "engine": "sqli_probe",
            "sub_type": "boolean_based",
            "true_payload": "1' AND '1'='1",
            "false_payload": "1' AND '1'='2",
            "size_delta_ratio": 0.42,
        },
    }
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="detector"
    )

    assert payload["account_id"] == 1000000
    assert payload["template_id"] == "AGENTIC:DETECTOR:SQLI"
    assert payload["endpoint_id"] == "ep-1"
    assert payload["type"] == "SQLI"
    assert payload["severity"] == "HIGH"
    assert payload["status"] == "OPEN"
    evidence = payload["evidence"]
    assert evidence["finding_status"] == "CONFIRMED"
    assert evidence["matched_rule"]["detector"] == "sqli_probe"
    assert evidence["matched_rule"]["sub_type"] == "boolean_based"
    assert evidence["evidence_completeness"]["complete"] is True
    assert verify_vulnerability_evidence(evidence)["verified"] is True


def test_chain_finding_uses_chain_dict_and_attacker_status():
    finding = {
        "type": "BOLA",
        "endpoint_id": "ep-1",
        "severity": "HIGH",
        "confidence": "HIGH",
        "rationale": "2-step chain: source exposes id, target consumes id",
        "chain": {
            "engine": "attack_chain",
            "steps": 2,
            "attacker_target_status": 200,
            "control_status": 401,
            "control_indicates_public": False,
        },
    }
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="chain"
    )

    assert payload["template_id"] == "AGENTIC:CHAIN:BOLA"
    assert payload["confidence"] == "HIGH"
    evidence = payload["evidence"]
    assert evidence["matched_rule"]["detector"] == "attack_chain"
    assert evidence["received_response"] == {"status_code": 200}
    assert "2-step chain" in evidence["remediation"]
    assert evidence["evidence_completeness"]["complete"] is True
    assert verify_vulnerability_evidence(evidence)["verified"] is True


def test_agentic_llm_finding_without_status_code_still_completes():
    finding = {
        "type": "BFLA",
        "endpoint_id": "ep-1",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "rationale": "low-privilege role invoked a privileged function",
        "evidence": {
            "engine": "bfla_matrix",
            "privileged_role": "ADMIN",
            "low_privilege_role": "MEMBER",
        },
    }
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="agentic"
    )

    evidence = payload["evidence"]
    assert evidence["received_response"] == {
        "privileged_role": "ADMIN",
        "low_privilege_role": "MEMBER",
    }
    assert evidence["evidence_completeness"]["complete"] is True
    assert verify_vulnerability_evidence(evidence)["verified"] is True


def test_minimal_evidence_with_only_engine_and_subtype_still_completes():
    """A detector evidence dict carrying ONLY engine/sub_type (no status_code,
    no other fields) must not collapse received_response to an empty dict —
    that would fail evidence_completeness even though the finding is real."""
    finding = {
        "type": "SQLI",
        "endpoint_id": "ep-1",
        "severity": "HIGH",
        "evidence": {"engine": "sqli_probe", "sub_type": "boolean_based"},
    }
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="detector"
    )
    evidence = payload["evidence"]
    assert evidence["received_response"] != {}
    assert evidence["evidence_completeness"]["complete"] is True
    assert verify_vulnerability_evidence(evidence)["verified"] is True


def test_missing_evidence_and_chain_still_produces_valid_payload():
    finding = {"type": "UNKNOWN_ISSUE", "endpoint_id": "ep-1", "severity": "MEDIUM"}
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="detector"
    )
    assert payload["type"] == "UNKNOWN_ISSUE"
    assert payload["evidence"]["matched_rule"]["detector"] == "agentic_detector"


def test_redacts_secrets_in_evidence_and_rationale():
    finding = {
        "type": "SQLI",
        "severity": "HIGH",
        "rationale": "leaked Authorization: Bearer raw-secret-token in response",
        "evidence": {"engine": "sqli_probe", "payload": "token=raw-secret-token"},
    }
    payload = build_agentic_vulnerability_data(
        finding=finding, endpoint=_ENDPOINT, account_id=1000000, source="detector"
    )
    blob = str(payload)
    assert "raw-secret-token" not in blob
