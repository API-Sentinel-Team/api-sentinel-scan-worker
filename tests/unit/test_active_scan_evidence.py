from sqlalchemy import select
import pytest

from sentinel_core.models import core as models
from sentinel_core.modules.test_executor.evidence import build_active_scan_evidence
from sentinel_worker.modules.test_executor.result_aggregator import ResultAggregator
from sentinel_core.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    verify_vulnerability_evidence,
)


def test_active_scan_evidence_is_redacted_and_deterministic():
    endpoint = {
        "id": "endpoint-1",
        "method": "GET",
        "url": "https://api.example.com/admin?token=raw-query-token",
    }
    result = {
        "template_id": "auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": True,
        "context_variables": ["baseline", "auth_context"],
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/admin?token=raw-query-token",
            "headers": {
                "Authorization": "Bearer raw-token",
                "Cookie": "sid=raw-session",
            },
            "body": '{"password":"raw-password","ok":"value"}',
        },
        "received_response": {
            "status_code": 200,
            "headers": {"Set-Cookie": "sid=raw-response"},
            "body": '{"api_key":"raw-key","ok":"value"}',
        },
        "results": [{"vulnerable": True, "proof": "Authorization: Bearer raw-token"}],
    }

    first = build_active_scan_evidence(result, endpoint)
    second = build_active_scan_evidence(result, endpoint)
    blob = str(first)

    assert first["evidence_hash"] == second["evidence_hash"]
    assert first["hash_algorithm"] == "sha256"
    assert first["finding_status"] == "UNCONFIRMED"
    assert first["retest_support"] == {
        "supported": True,
        "queued_scan_supported": True,
        "manual_outcome_supported": True,
        "reason": "queued_scan_available",
        "missing_fields": [],
    }
    assert first["evidence_reproducibility"] == {
        "redaction_policy": "api_sentinel_redactor",
        "raw_payload_persisted": False,
        "deterministic_hash": True,
        "hash_algorithm": "sha256",
        "reproduction_available": True,
        "scope_validated": False,
        "evidence_complete": False,
    }
    assert first["sent_request"]["url"] == "https://api.example.com/admin?token=****"
    assert first["sent_request"]["headers"]["Authorization"] == "Bearer ****"
    assert "curl -i -X GET" in first["reproduction"]["curl"]
    assert "token=****" in first["reproduction"]["curl"]
    assert "raw-token" not in blob
    assert "raw-session" not in blob
    assert "raw-password" not in blob
    assert "raw-key" not in blob


def test_active_scan_evidence_records_disproven_confirmatory_retest():
    endpoint = {
        "id": "endpoint-1",
        "method": "GET",
        "url": "https://api.example.com/admin?token=raw-query-token",
    }
    result = {
        "template_id": "auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": False,
        "skip_reason": "confirmatory_retest_failed",
        "original_evidence": "Authorization: Bearer raw-token token=raw-token",
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/admin?token=raw-query-token",
            "headers": {"Authorization": "Bearer raw-token"},
        },
        "received_response": {"status_code": 200, "body": '{"ok":"value"}'},
        "results": [{"vulnerable": True, "proof": "Authorization: Bearer raw-token"}],
        "confirmation": {
            "required": True,
            "confirmed": False,
            "sent_request": {
                "url": "https://api.example.com/admin?token=raw-confirmation-query-token",
                "headers": {"Authorization": "Bearer raw-confirmation-token"},
            },
            "received_response": {"status_code": 200, "body": '{"token":"raw-confirmation-body-token"}'},
            "results": [{"vulnerable": False, "proof": "clean token=raw-confirmation-token"}],
        },
    }

    evidence = build_active_scan_evidence(result, endpoint)
    blob = str(evidence)

    assert evidence["finding_status"] == "DISPROVEN"
    assert evidence["skip_reason"] == "confirmatory_retest_failed"
    assert evidence["confirmation"]["confirmed"] is False
    assert evidence["observation"] == "Authorization: Bearer **** token=****"
    assert evidence["evidence_hash"]
    assert confirmation_status_from_evidence(evidence) == "DISPROVEN"
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    assert "raw-token" not in blob
    assert "raw-confirmation-token" not in blob
    assert "raw-confirmation-body-token" not in blob


def test_active_scan_evidence_preserves_redacted_safety_policy_metadata():
    endpoint = {
        "id": "endpoint-safety",
        "method": "GET",
        "url": "https://api.example.com/orders?token=raw-query-token",
    }
    policy = {
        "policy": "auth_profile_scope_guard",
        "blocked": True,
        "url": "https://api.example.com/orders?token=raw-query-token",
        "base_url": "https://api.example.com/orders?token=raw-query-token",
        "reason": "Authorization: Bearer raw-token token=raw-token",
        "auth_profile_id": "auth-profile-1",
        "scope_domains_configured": True,
        "scope_domain_count": 1,
    }
    result = {
        "template_id": "auth-scope-blocked",
        "severity": "LOW",
        "is_vulnerable": False,
        "skip_reason": "auth_profile_scope_guard",
        "evidence": "auth_profile_scope_guard=blocked token=raw-token",
        "auth_profile_scope_policy": policy,
        "results": [
            {
                "vulnerable": False,
                "error": "Authorization: Bearer raw-token token=raw-token",
                "auth_profile_scope_policy": policy,
            }
        ],
    }

    evidence = build_active_scan_evidence(result, endpoint)
    blob = str(evidence)

    assert evidence["skip_reason"] == "auth_profile_scope_guard"
    assert evidence["safety_policies"]["auth_profile_scope_policy"]["url"] == (
        "https://api.example.com/orders?token=****"
    )
    assert evidence["safety_policies"]["auth_profile_scope_policy"]["reason"] == (
        "Authorization: Bearer **** token=****"
    )
    assert evidence["results"][0]["auth_profile_scope_policy"]["url"] == "https://api.example.com/orders?token=****"
    assert evidence["results"][0]["auth_profile_scope_policy"]["reason"] == "Authorization: Bearer **** token=****"
    assert "raw-token" not in blob
    assert "raw-query-token" not in blob
    assert evidence["evidence_hash"]


def test_active_scan_evidence_lifts_allowed_target_guard_policy_to_scope_validation():
    endpoint = {
        "id": "endpoint-scope",
        "method": "GET",
        "url": "https://api.example.com/orders?token=raw-query-token",
    }
    result = {
        "template_id": "auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": True,
        "sent_request": {"method": "GET", "url": endpoint["url"]},
        "received_response": {"status_code": 200},
        "results": [{"vulnerable": True}],
        "safety_policies": {
            "target_guard_policy": {
                "policy": "target_guard",
                "blocked": False,
                "url": "https://api.example.com/orders?token=raw-query-token",
                "base_url": "https://api.example.com/orders?token=raw-query-token",
            },
            "state_change_policy": {
                "policy": "state_change_guard",
                "method": "GET",
                "destructive_method": False,
                "allow_state_change": False,
                "allow_destructive_methods": False,
            },
        },
    }

    evidence = build_active_scan_evidence(result, endpoint)

    assert evidence["scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com/orders?token=****",
        "evidence_url": "https://api.example.com/orders?token=****",
    }
    assert evidence["evidence_reproducibility"]["scope_validated"] is True
    assert "raw-query-token" not in str(evidence)


def test_active_scan_evidence_reports_complete_evidence_grade_contract():
    endpoint = {
        "id": "endpoint-contract",
        "method": "POST",
        "url": "https://api.example.com/admin/users?token=raw-query-token",
    }
    result = {
        "template_id": "auth-bypass",
        "rule_id": "status-code-match",
        "rule_idx": 1,
        "severity": "HIGH",
        "is_vulnerable": True,
        "matched_rule": {
            "name": "Admin access with Authorization: Bearer raw-token",
            "description": "Matched token=raw-rule-token",
        },
        "similarity_pct": 97.25,
        "remediation": "Remove the bypass and rotate token=raw-remediation-token",
        "sent_request": {
            "method": "POST",
            "url": "https://api.example.com/admin/users?token=raw-query-token",
            "headers": {"Authorization": "Bearer raw-token"},
            "body": '{"user_id":"123"}',
        },
        "received_response": {
            "status_code": 200,
            "headers": {"Set-Cookie": "sid=raw-response-session"},
            "body": '{"ok": true}',
        },
        "results": [{"vulnerable": True, "proof": "Authorization: Bearer raw-token"}],
    }

    evidence = build_active_scan_evidence(result, endpoint)
    blob = str(evidence)

    assert evidence["matched_rule"] == {
        "template_id": "auth-bypass",
        "rule_id": "status-code-match",
        "rule_idx": 1,
        "name": "Admin access with Authorization: Bearer ****",
        "description": "Matched token=****",
    }
    assert evidence["similarity"] == {"similarity_pct": 97.25}
    assert evidence["remediation"] == "Remove the bypass and rotate token=****"
    assert evidence["evidence_completeness"]["complete"] is True
    assert evidence["evidence_completeness"]["missing"] == []
    assert evidence["evidence_completeness"]["required"] == [
        "status",
        "matched_rule",
        "sent_request",
        "received_response",
        "similarity",
        "reproduction",
        "remediation",
    ]
    assert "raw-token" not in blob
    assert "raw-rule-token" not in blob
    assert "raw-remediation-token" not in blob
    assert evidence["evidence_hash"]


def test_active_scan_evidence_preserves_business_logic_scenario_contract_without_values():
    endpoint = {
        "id": "endpoint-business-logic",
        "method": "POST",
        "url": "https://api.example.com/checkout/confirm?token=raw-query-token",
    }
    result = {
        "template_id": "business-logic-workflow-direct-entry",
        "severity": "HIGH",
        "is_vulnerable": True,
        "security_category": "business_logic",
        "active_business_logic": {
            "scenario_type": "workflow_direct_entry",
            "abuse_family": "workflow_bypass",
            "endpoint_id": "endpoint-business-logic",
            "path": "/checkout/confirm?token=raw-scenario-token",
            "safe_throttle": {
                "max_requests": 1,
                "per_endpoint": True,
                "honor_retry_after": True,
            },
            "deterministic_evidence": {
                "required": [
                    "scenario_type",
                    "safe_throttle",
                    "sent_request",
                    "received_response",
                    "response_code",
                    "matched_rule",
                ],
                "body_content_persisted": False,
                "matched_text_persisted": False,
                "promotion_decision": "promote_unconfirmed_finding",
            },
            "flow_mapping": {
                "graph_version": 7,
                "node_path": "/checkout/confirm?token=raw-node-token",
                "sensitive_flow": True,
                "sensitive_signals": ["private_variables_present"],
                "expected_predecessors": ["/cart?session=raw-session"],
                "expected_predecessor_count": 1,
            },
        },
        "matched_rule": {
            "rule_id": "workflow_direct_entry",
            "name": "Workflow direct entry accepted",
        },
        "similarity": {"confidence_score": 0.91},
        "sent_request": {
            "method": "POST",
            "url": "https://api.example.com/checkout/confirm?token=raw-query-token",
            "headers": {"Authorization": "Bearer raw-token"},
            "body": {"coupon_code": "raw-coupon", "order_id": "raw-order"},
        },
        "received_response": {
            "status_code": 200,
            "headers": {"Set-Cookie": "sid=raw-response-session"},
        },
        "results": [{"vulnerable": True, "proof": "session=raw-session"}],
    }

    evidence = build_active_scan_evidence(result, endpoint)
    blob = str(evidence)

    assert evidence["security_category"] == "business_logic"
    assert evidence["business_logic_scenario"] == {
        "scenario_type": "workflow_direct_entry",
        "abuse_family": "workflow_bypass",
        "endpoint_id": "endpoint-business-logic",
        "path": "/checkout/confirm?token=****",
        "safe_throttle": {
            "max_requests": 1,
            "per_endpoint": True,
            "honor_retry_after": True,
        },
        "deterministic_evidence": {
            "required": [
                "scenario_type",
                "safe_throttle",
                "sent_request",
                "received_response",
                "response_code",
                "matched_rule",
            ],
            "body_content_persisted": False,
            "matched_text_persisted": False,
            "promotion_decision": "promote_unconfirmed_finding",
        },
        "flow_mapping": {
            "graph_version": 7,
            "node_path": "/checkout/confirm?token=****",
            "sensitive_flow": True,
            "sensitive_signals": ["private_variables_present"],
            "expected_predecessors": ["/cart?session=****"],
            "expected_predecessor_count": 1,
        },
    }
    assert evidence["content_minimization"]["business_logic_scenario_content_persisted"] is True
    assert evidence["evidence_hash"]
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    assert "raw-" not in blob


def test_active_scan_evidence_names_missing_grade_fields_without_leaking_secrets():
    endpoint = {
        "id": "endpoint-incomplete",
        "method": "GET",
        "url": "https://api.example.com/admin?token=raw-query-token",
    }
    result = {
        "template_id": "auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": True,
        "evidence": "Authorization: Bearer raw-token",
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/admin?token=raw-query-token",
            "headers": {"Authorization": "Bearer raw-token"},
        },
    }

    evidence = build_active_scan_evidence(result, endpoint)
    blob = str(evidence)

    assert evidence["evidence_completeness"]["complete"] is False
    assert evidence["evidence_completeness"]["missing"] == [
        "matched_rule",
        "received_response",
        "similarity",
    ]
    assert evidence["remediation"]
    assert "raw-token" not in blob
    assert "raw-query-token" not in blob


@pytest.mark.asyncio
async def test_result_aggregator_persists_reproducible_active_scan_evidence(db_session):
    endpoint = {
        "id": "endpoint-agg",
        "account_id": 1000000,
        "method": "GET",
        "path": "/admin",
        "url": "https://api.example.com/admin?token=raw-query-token",
    }
    result = {
        "template_id": "confirmed-auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": True,
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/admin?token=raw-query-token",
            "headers": {"Authorization": "Bearer raw-token"},
        },
        "received_response": {"status_code": 200, "body": '{"ok": true}'},
        "results": [{"vulnerable": True}],
        "confirmation": {"confirmed": True, "sent_request": {"headers": {"Authorization": "Bearer raw-token"}}},
    }

    await ResultAggregator(db=db_session).add_vulnerability(result, endpoint)
    await db_session.commit()

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "confirmed-auth-bypass")
        )
    ).scalar_one()
    evidence = vulnerability.evidence
    blob = str(evidence)

    assert evidence["engine"] == "template"
    assert evidence["sent_request"]["headers"]["Authorization"] == "Bearer ****"
    assert evidence["confirmation"]["confirmed"] is True
    assert evidence["evidence_hash"]
    assert vulnerability.remediation == evidence["remediation"]
    assert "curl -i -X GET" in evidence["reproduction"]["curl"]
    assert "raw-token" not in blob
    assert "raw-query-token" not in blob


@pytest.mark.asyncio
async def test_result_aggregator_merges_active_scan_retest_with_changed_evidence(db_session):
    endpoint = {
        "id": "endpoint-merge",
        "account_id": 1000000,
        "method": "GET",
        "path": "/admin",
        "url": "https://api.example.com/admin",
    }
    base_result = {
        "template_id": "stable-auth-bypass",
        "severity": "HIGH",
        "is_vulnerable": True,
        "sent_request": {
            "method": "GET",
            "url": "https://api.example.com/admin",
            "headers": {"Authorization": "Bearer raw-token"},
        },
        "confirmation": {"confirmed": True},
    }

    await ResultAggregator(db=db_session).add_vulnerability(
        {
            **base_result,
            "received_response": {"status_code": 200, "body": '{"ok": true}'},
            "results": [{"vulnerable": True, "proof": "first proof"}],
        },
        endpoint,
    )
    await ResultAggregator(db=db_session).add_vulnerability(
        {
            **base_result,
            "received_response": {"status_code": 503, "body": '{"transient": true}'},
            "results": [{"vulnerable": True, "proof": "second proof"}],
        },
        endpoint,
    )
    await db_session.commit()

    vulnerabilities = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "stable-auth-bypass")
        )
    ).scalars().all()

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].occurrence_count == 2
    assert vulnerabilities[0].evidence["lifecycle"]["occurrence_count"] == 2
