from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from server.modules.utils.redactor import Redactor

_ACTIVE_EVIDENCE_DIGEST_IGNORED_KEYS = {
    "evidence_hash",
    "hash_algorithm",
    "lifecycle",
    "occurrences",
    "remediation_retests",
    "latest_remediation_retest",
    "remediation_events",
    "latest_remediation_event",
    "ticket_syncs",
    "latest_ticket_sync",
    "lifecycle_events",
    "latest_lifecycle_event",
    "observation_metadata",
}

_DEFAULT_REMEDIATION = (
    "Validate the affected endpoint, fix the vulnerable authorization/input handling path, "
    "and rerun the API Sentinel confirmatory retest."
)

_EVIDENCE_COMPLETENESS_FIELDS = [
    "status",
    "matched_rule",
    "sent_request",
    "received_response",
    "similarity",
    "reproduction",
    "remediation",
]

_MATCHED_RULE_KEYS = (
    "template_id",
    "rule_id",
    "rule_idx",
    "name",
    "description",
    "matcher",
    "extractor",
    "condition",
)

_SIMILARITY_KEYS = (
    "similarity_pct",
    "percentage_match",
    "body_similarity_pct",
    "schema_similarity_pct",
    "response_similarity_pct",
    "confidence_score",
)


def build_active_scan_evidence(test_result: dict[str, Any], endpoint: dict[str, Any]) -> dict[str, Any]:
    """Build deterministic, redacted evidence for an active template scan finding."""
    redacted_result = Redactor.redact_scan_result(test_result)
    endpoint_url = str(endpoint.get("url") or endpoint.get("path") or "")
    endpoint_method = str(endpoint.get("method") or "GET").upper()
    llm_judge_validation = _llm_judge_validation(redacted_result)
    business_logic_scenario = _business_logic_scenario_metadata(redacted_result)
    sent_request = _redacted_request(redacted_result.get("sent_request"), method=endpoint_method, url=endpoint_url)
    received_response = Redactor.redact_http_message(redacted_result.get("received_response"))
    if llm_judge_validation or business_logic_scenario:
        sent_request.pop("body", None)
        if isinstance(received_response, dict):
            received_response = dict(received_response)
            received_response.pop("body", None)

    evidence: dict[str, Any] = {
        "engine": "template",
        "template_id": redacted_result.get("template_id"),
        "severity": redacted_result.get("severity"),
        "finding_status": "UNCONFIRMED",
        "endpoint": {
            "id": str(endpoint.get("id") or ""),
            "method": endpoint_method,
            "url": Redactor.redact_url(endpoint_url),
        },
        "sent_request": sent_request,
        "received_response": received_response,
        "results": redacted_result.get("results", []),
        "context": sorted(str(item) for item in (redacted_result.get("context_variables") or [])),
    }
    if redacted_result.get("security_category"):
        evidence["security_category"] = Redactor.redact_text(str(redacted_result["security_category"]))
    if business_logic_scenario:
        evidence.setdefault("security_category", "business_logic")
        evidence["business_logic_scenario"] = business_logic_scenario
    if llm_judge_validation:
        evidence["llm_judge_validation"] = llm_judge_validation
        evidence["judge_validation"] = llm_judge_validation
    if redacted_result.get("skip_reason"):
        evidence["skip_reason"] = Redactor.redact_text(str(redacted_result["skip_reason"]))

    safety_policies = _safety_policy_metadata(redacted_result)
    if safety_policies:
        evidence["safety_policies"] = safety_policies
        scope_validation = _scope_validation_from_safety_policies(safety_policies)
        if scope_validation:
            evidence["scope_validation"] = scope_validation

    evidence["retest_support"] = _retest_support_metadata(
        template_id=evidence.get("template_id"),
        endpoint_id=evidence["endpoint"]["id"],
    )

    observation = redacted_result.get("original_evidence", redacted_result.get("evidence"))
    if observation not in (None, ""):
        evidence["observation"] = _redacted_observation(observation)

    matched_rule = _matched_rule_metadata(redacted_result)
    if matched_rule:
        evidence["matched_rule"] = matched_rule

    similarity = _similarity_metadata(redacted_result)
    if similarity:
        evidence["similarity"] = similarity

    if redacted_result.get("confirmation"):
        confirmation = Redactor.redact_scan_result(redacted_result["confirmation"])
        evidence["confirmation"] = confirmation
        if isinstance(confirmation, dict) and confirmation.get("confirmed") is True:
            evidence["finding_status"] = "CONFIRMED"
        elif isinstance(confirmation, dict) and confirmation.get("confirmed") is False:
            evidence["finding_status"] = "DISPROVEN"

    curl = build_redacted_curl(sent_request)
    if curl:
        evidence["reproduction"] = {"curl": curl}

    evidence["remediation"] = _remediation_text(redacted_result)
    evidence["evidence_completeness"] = _evidence_completeness(evidence)
    evidence["content_minimization"] = content_minimization_contract(evidence)
    evidence["hash_algorithm"] = "sha256"
    evidence["evidence_reproducibility"] = evidence_reproducibility_contract(evidence)
    evidence["evidence_hash"] = evidence_digest(evidence)
    return evidence


def evidence_digest(evidence: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in evidence.items()
        if key not in _ACTIVE_EVIDENCE_DIGEST_IGNORED_KEYS
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def finalize_finding_evidence(
    evidence: dict[str, Any],
    *,
    method: str,
    url: str,
    matched_rule: dict[str, Any] | None,
    received_response: dict[str, Any] | None,
    similarity: dict[str, Any] | None,
    remediation: str,
    finding_status: str = "UNCONFIRMED",
    sent_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add the shared evidence-grade contract and deterministic hash."""
    payload = dict(evidence)
    normalized_method = str(method or "GET").upper()
    normalized_url = str(url or "")

    payload["finding_status"] = str(finding_status or "UNCONFIRMED").upper()
    if matched_rule:
        payload["matched_rule"] = _redact_metadata(matched_rule)

    request = sent_request or {"method": normalized_method, "url": normalized_url}
    payload["sent_request"] = _redacted_request(
        request,
        method=normalized_method,
        url=normalized_url,
    )

    safe_response = Redactor.redact_http_message(received_response or {})
    payload["received_response"] = safe_response if isinstance(safe_response, dict) else {}

    if similarity:
        payload["similarity"] = _redact_metadata(similarity)

    curl = build_redacted_curl(payload["sent_request"])
    if curl:
        payload["reproduction"] = {"curl": curl}

    payload["remediation"] = Redactor.redact_text(str(remediation or _DEFAULT_REMEDIATION))
    payload.setdefault(
        "retest_support",
        _retest_support_metadata(template_id=payload.get("template_id"), endpoint_id=None),
    )
    payload["evidence_completeness"] = _evidence_completeness(payload)
    payload["content_minimization"] = content_minimization_contract(payload)
    payload["hash_algorithm"] = "sha256"
    payload["evidence_reproducibility"] = evidence_reproducibility_contract(payload)
    payload["evidence_hash"] = evidence_digest(payload)
    return payload


def build_redacted_curl(request: dict[str, Any] | None) -> str:
    if not isinstance(request, dict):
        return ""

    method = str(request.get("method") or "GET").upper()
    url = str(request.get("url") or "")
    if not url:
        return ""

    parts = ["curl", "-i", "-X", method, _shell_quote(Redactor.redact_url(url))]
    headers = Redactor.redact_headers(request.get("headers") or {}) if isinstance(request.get("headers"), dict) else {}
    for key, value in sorted(headers.items()):
        parts.extend(["-H", _shell_quote(f"{key}: {value}")])

    body = request.get("body")
    if body not in (None, ""):
        safe_body = Redactor.redact_json(body)
        body_text = json.dumps(safe_body, sort_keys=True) if not isinstance(safe_body, str) else safe_body
        parts.extend(["--data", _shell_quote(body_text)])
    return " ".join(parts)


def _redacted_request(raw_request: Any, *, method: str, url: str) -> dict[str, Any]:
    request = Redactor.redact_http_message(raw_request) if isinstance(raw_request, dict) else {}
    request = dict(request or {})
    request.setdefault("method", method)
    request.setdefault("url", Redactor.redact_url(url))
    if "headers" in request and isinstance(request["headers"], dict):
        request["headers"] = dict(sorted(request["headers"].items()))
    return request


def _redacted_observation(value: Any) -> Any:
    if isinstance(value, str):
        return Redactor.redact_text(value)
    return Redactor.redact_json(value)


def _safety_policy_metadata(test_result: dict[str, Any]) -> dict[str, Any]:
    policy_keys = (
        "auth_profile_scope_policy",
        "state_change_policy",
        "target_guard_policy",
    )
    policies = {}
    nested_policies = test_result.get("safety_policies")
    if isinstance(nested_policies, dict):
        policies.update(
            {
                key: value
                for key in policy_keys
                if isinstance((value := nested_policies.get(key)), dict)
            }
        )
    policies.update({
        key: value
        for key in policy_keys
        if isinstance((value := test_result.get(key)), dict)
    })
    return policies


def _scope_validation_from_safety_policies(policies: dict[str, Any]) -> dict[str, Any]:
    target_policy = policies.get("target_guard_policy")
    if not isinstance(target_policy, dict) or target_policy.get("blocked") is not False:
        return {}
    evidence_url = str(target_policy.get("url") or "")
    target = str(target_policy.get("base_url") or evidence_url)
    return {
        "validated": True,
        "policy": "target_guard",
        "scope": str(target_policy.get("scope") or "same_origin_or_allowlisted"),
        "target": Redactor.redact_url(target),
        "evidence_url": Redactor.redact_url(evidence_url),
    }


def _retest_support_metadata(*, template_id: Any, endpoint_id: Any) -> dict[str, Any]:
    missing_fields = [
        field
        for field, value in (("template_id", template_id), ("endpoint_id", endpoint_id))
        if value in (None, "")
    ]
    queued_scan_supported = not missing_fields
    return {
        "supported": True,
        "queued_scan_supported": queued_scan_supported,
        "manual_outcome_supported": True,
        "reason": "queued_scan_available" if queued_scan_supported else "manual_or_external_retest_required",
        "missing_fields": missing_fields,
    }


def _matched_rule_metadata(test_result: dict[str, Any]) -> dict[str, Any]:
    raw_rule = test_result.get("matched_rule")
    metadata: dict[str, Any] = {}
    has_rule_signal = False
    if isinstance(raw_rule, dict):
        metadata.update(
            {
                key: raw_rule[key]
                for key in _MATCHED_RULE_KEYS
                if raw_rule.get(key) not in (None, "")
            }
        )
        has_rule_signal = bool(metadata)
    elif raw_rule not in (None, ""):
        metadata["name"] = raw_rule
        has_rule_signal = True

    for key in ("rule_id", "rule_idx"):
        if test_result.get(key) not in (None, ""):
            metadata.setdefault(key, test_result[key])
            has_rule_signal = True

    if not has_rule_signal:
        return {}

    if test_result.get("template_id") not in (None, ""):
        metadata.setdefault("template_id", test_result["template_id"])

    return _redact_metadata(metadata)


def _similarity_metadata(test_result: dict[str, Any]) -> dict[str, Any]:
    if isinstance(test_result.get("similarity"), dict):
        return _redact_metadata(test_result["similarity"])

    metadata = {
        key: test_result[key]
        for key in _SIMILARITY_KEYS
        if test_result.get(key) not in (None, "")
    }
    if metadata:
        return _redact_metadata(metadata)

    results = test_result.get("results")
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            nested = {
                key: item[key]
                for key in _SIMILARITY_KEYS
                if item.get(key) not in (None, "")
            }
            if nested:
                return _redact_metadata(nested)

    return {}


def _llm_judge_validation(test_result: dict[str, Any]) -> dict[str, Any]:
    validation = test_result.get("llm_judge_validation")
    if not isinstance(validation, dict):
        return {}
    safe_validation = Redactor.redact_json(validation)
    if not isinstance(safe_validation, dict):
        return {}
    safe_validation["body_content_persisted"] = False
    safe_validation["matched_text_persisted"] = False
    content_minimization = safe_validation.get("content_minimization")
    if isinstance(content_minimization, dict):
        content_minimization["raw_request_body_persisted"] = False
        content_minimization["raw_response_body_persisted"] = False
        content_minimization["matched_text_persisted"] = False
        content_minimization["secret_values_persisted"] = False
    return safe_validation


def _business_logic_scenario_metadata(test_result: dict[str, Any]) -> dict[str, Any]:
    scenario = test_result.get("active_business_logic")
    if not isinstance(scenario, dict):
        return {}
    redacted = Redactor.redact_json(scenario)
    if not isinstance(redacted, dict):
        return {}

    metadata: dict[str, Any] = {}
    for key in ("scenario_type", "abuse_family", "endpoint_id", "path"):
        if redacted.get(key) not in (None, ""):
            metadata[key] = redacted[key]

    safe_throttle = redacted.get("safe_throttle")
    if isinstance(safe_throttle, dict):
        metadata["safe_throttle"] = {
            key: safe_throttle[key]
            for key in ("max_requests", "per_endpoint", "honor_retry_after")
            if key in safe_throttle
        }

    deterministic_evidence = redacted.get("deterministic_evidence")
    if isinstance(deterministic_evidence, dict):
        metadata["deterministic_evidence"] = {
            key: deterministic_evidence[key]
            for key in (
                "required",
                "body_content_persisted",
                "matched_text_persisted",
                "promotion_decision",
            )
            if key in deterministic_evidence
        }

    flow_mapping = redacted.get("flow_mapping")
    if isinstance(flow_mapping, dict):
        metadata["flow_mapping"] = {
            key: flow_mapping[key]
            for key in (
                "graph_version",
                "node_path",
                "sensitive_flow",
                "sensitive_signals",
                "expected_predecessors",
                "expected_predecessor_count",
                "node_observed",
                "flow_id",
            )
            if key in flow_mapping
        }

    return metadata


def _remediation_text(test_result: dict[str, Any]) -> str:
    value = test_result.get("remediation") or test_result.get("recommendation") or _DEFAULT_REMEDIATION
    return Redactor.redact_text(str(value))


def _evidence_completeness(evidence: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "status": bool(evidence.get("finding_status")),
        "matched_rule": bool(evidence.get("matched_rule")),
        "sent_request": _has_sent_request(evidence.get("sent_request")),
        "received_response": _has_received_response(evidence.get("received_response")),
        "similarity": bool(evidence.get("similarity")),
        "reproduction": bool((evidence.get("reproduction") or {}).get("curl")),
        "remediation": bool(evidence.get("remediation")),
    }
    present = [field for field in _EVIDENCE_COMPLETENESS_FIELDS if checks[field]]
    missing = [field for field in _EVIDENCE_COMPLETENESS_FIELDS if not checks[field]]
    return {
        "complete": not missing,
        "required": list(_EVIDENCE_COMPLETENESS_FIELDS),
        "present": present,
        "missing": missing,
    }


def _has_sent_request(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("method")) and bool(value.get("url"))


def _has_received_response(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    if "status_code" in value:
        status = value.get("status_code")
        if isinstance(status, int) and status > 0:
            return True
        # For engines that don't emit a numeric status code, accept a non-empty
        # body (e.g. schemathesis external-report mode before HTTP extraction is
        # available). A present-but-falsy status_code (0/None) with no body means
        # the engine never actually observed a response — that's the case this
        # check exists to catch.
        return bool(value.get("body"))
    # Non-HTTP evidence shapes (passive traffic PII location, business-logic
    # graph transitions) never carry a status_code at all — any genuine,
    # non-empty observation counts as a received response for those engines.
    return any(item not in (None, "", {}, []) for item in value.values())


def evidence_reproducibility_contract(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return the shared redacted, reproducible evidence contract."""

    completeness = evidence.get("evidence_completeness")
    scope_validation = evidence.get("scope_validation")
    return {
        "redaction_policy": "api_sentinel_redactor",
        "raw_payload_persisted": False,
        "deterministic_hash": True,
        "hash_algorithm": str(evidence.get("hash_algorithm") or "sha256"),
        "reproduction_available": bool((evidence.get("reproduction") or {}).get("curl")),
        "scope_validated": bool(
            isinstance(scope_validation, dict)
            and scope_validation.get("validated") is True
        ),
        "evidence_complete": bool(
            isinstance(completeness, dict)
            and completeness.get("complete") is True
        ),
    }


def content_minimization_contract(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return the shared proof that stored evidence is redacted and minimized."""

    sent_request = evidence.get("sent_request")
    received_response = evidence.get("received_response")
    body_content_persisted = (
        isinstance(sent_request, dict)
        and sent_request.get("body") not in (None, "", {}, [])
    ) or (
        isinstance(received_response, dict)
        and received_response.get("body") not in (None, "", {}, [])
    )
    persisted_material = ["metadata"]
    if _has_sent_request(sent_request) or _has_received_response(received_response):
        persisted_material.append("redacted_http_messages")
    if (evidence.get("reproduction") or {}).get("curl"):
        persisted_material.append("redacted_reproduction")
    if isinstance(evidence.get("business_logic_scenario"), dict):
        persisted_material.append("redacted_business_logic_scenario")
    persisted_material.append("sha256_digests")

    return {
        "raw_request_body_persisted": False,
        "raw_response_body_persisted": False,
        "matched_text_persisted": False,
        "secret_values_persisted": False,
        "body_content_persisted": bool(body_content_persisted),
        "business_logic_scenario_content_persisted": isinstance(evidence.get("business_logic_scenario"), dict),
        "details_content_persisted": True,
        "persisted_material": persisted_material,
    }


def _redact_metadata(value: dict[str, Any]) -> dict[str, Any]:
    redacted = Redactor.redact_json(value)
    return redacted if isinstance(redacted, dict) else {}


def _shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"
