from __future__ import annotations

import hmac
import json
import re
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

from server.config import settings
from server.modules.business_logic.active_testing import business_abuse_family_coverage
from server.modules.test_executor.selection_filter import SelectionFilterEngine
from server.modules.utils.redactor import Redactor


_INTENSITY_ALIASES = {
    "safe": "safe",
    "standard": "standard",
    "balanced": "standard",
    "normal": "standard",
    "aggressive": "aggressive",
}
_SENSITIVE_FIELD_RE = re.compile(
    r"password|passwd|pwd|token|secret|authorization|auth|cookie|session|csrf|credential|api[_-]?key",
    re.IGNORECASE,
)
_PRIVATE_PARAMETER_RE = re.compile(
    r"(^|[_-])(user|account|tenant|org|organization|customer|member|owner|profile|order|invoice|project|resource|object|item|id|uuid)([_-]|$)|id$|uuid$",
    re.IGNORECASE,
)
_LLM_PATH_RE = re.compile(r"/(chat|completions|responses|generate|prompt|llm|ai|agent|assistant|model)(/|$)", re.IGNORECASE)
_LLM_BODY_KEYS = {
    "assistant",
    "input",
    "instructions",
    "messages",
    "model",
    "prompt",
    "system",
    "tools",
}
_TOOL_CONTEXT_KEYS = {
    "function_call",
    "function_calls",
    "tool_call",
    "tool_calls",
    "tool_output",
    "tool_outputs",
    "tool_result",
    "tool_results",
    "tools",
}
_RAG_CONTEXT_KEYS = {
    "retrieved_context",
    "retrieved_documents",
    "source_documents",
    "source_docs",
    "citations",
    "references",
    "chunks",
    "page_content",
}
_TOOL_OUTPUT_CONTEXT_KEYS = {
    "tool_output",
    "tool_outputs",
    "tool_result",
    "tool_results",
    "tool_observation",
    "tool_observations",
    "tool_response",
    "tool_responses",
    "function_result",
    "function_results",
    "observations",
}
_TOOL_INVOCATION_CONTEXT_KEYS = {
    "arguments",
    "function",
    "function_call",
    "function_calls",
    "name",
    "tool_call",
    "tool_calls",
    "tools",
}
_LLM_ACTIVE_FAMILY_ORDER = (
    "prompt_injection",
    "rag_exfiltration",
    "indirect_prompt_injection",
    "dangerous_tool_invocation",
    "privilege_escalating_tool_invocation",
    "tool_chain_injection",
)
_LLM_ACTIVE_FAMILY_CONFIG = {
    "prompt_injection": {
        "endpoint_required_signals": {"body_key"},
        "reported_signals": {"body_key", "path_hint"},
    },
    "rag_exfiltration": {
        "endpoint_required_signals": {"body_key", "retrieval_context"},
        "reported_signals": {"body_key", "retrieval_context"},
    },
    "indirect_prompt_injection": {
        "endpoint_required_signals": {"body_key", "untrusted_context"},
        "reported_signals": {
            "body_key",
            "retrieval_context",
            "tool_output_context",
            "untrusted_context",
        },
    },
    "dangerous_tool_invocation": {
        "endpoint_required_signals": {"body_key", "tool_invocation_context"},
        "reported_signals": {"body_key", "tool_invocation_context"},
    },
    "privilege_escalating_tool_invocation": {
        "endpoint_required_signals": {"body_key", "tool_invocation_context"},
        "reported_signals": {"body_key", "tool_invocation_context"},
    },
    "tool_chain_injection": {
        "endpoint_required_signals": {
            "body_key",
            "tool_invocation_context",
            "untrusted_context",
        },
        "reported_signals": {
            "body_key",
            "tool_invocation_context",
            "tool_output_context",
            "untrusted_context",
        },
    },
}
_BUSINESS_FLOW_PATH_RE = re.compile(
    r"/(cart|checkout|coupon|discount|payment|refund|transfer|otp|mfa|verify|verification|invoice|order|subscription)(/|$)",
    re.IGNORECASE,
)
_PRIVILEGED_ROLE_KEYS = {"ADMIN", "OWNER", "ROOT", "SUPERADMIN", "SUPER_ADMIN"}
_LOW_PRIVILEGE_ROLE_KEYS = {"ATTACKER", "GUEST", "MEMBER", "USER", "VIEWER", "READONLY", "READ_ONLY"}
_SCAN_PLAN_DIGEST_IGNORED_KEYS = {"scan_plan_hash", "hash_algorithm", "scan_plan_integrity"}


def normalize_test_intensity(value: str | None, *, profile: object | None = None) -> str:
    """Normalize user-facing scan intensity into the three runtime policy levels."""
    raw_value = value
    if raw_value is not None and not isinstance(raw_value, str) and hasattr(raw_value, "default"):
        raw_value = getattr(raw_value, "default", None)
    if raw_value is None and profile is not None:
        raw_value = getattr(profile, "mode", None)
    if raw_value is None:
        return "standard"

    normalized = str(raw_value).strip().lower()
    mapped = _INTENSITY_ALIASES.get(normalized)
    if mapped:
        return mapped
    raise ValueError("test_intensity: must be one of safe, standard, aggressive")


def endpoint_selection_context(endpoint: Any, *, account_id: int | None = None) -> dict[str, Any]:
    """Convert ORM/dict endpoint data into selector input without changing runtime semantics."""
    endpoint_id = _get(endpoint, "id")
    method = _get(endpoint, "method")
    protocol = _get(endpoint, "protocol") or "http"
    host = _get(endpoint, "host") or ""
    path = _get(endpoint, "path") or "/"
    url = _get(endpoint, "url")
    if not url and host:
        url = f"{protocol}://{host}{path}"

    context = {
        "id": str(endpoint_id) if endpoint_id is not None else None,
        "method": method,
        "url": url,
        "path": path,
        "host": host,
        "protocol": protocol,
        "last_response_body": _get(endpoint, "last_response_body"),
        "last_request_body": _get(endpoint, "last_request_body"),
        "last_query_string": _get(endpoint, "last_query_string"),
        "last_response_code": _get(endpoint, "last_response_code"),
        "last_response_headers": _get(endpoint, "last_response_headers") or {},
        "auth_types_found": _get(endpoint, "auth_types_found") or [],
        "private_variable_count": _get(endpoint, "private_variable_count") or 0,
        "account_id": account_id if account_id is not None else _get(endpoint, "account_id"),
    }
    for key in (
        "request_schema",
        "response_schema",
        "schema_json",
        "parameters",
        "sensitive_fields",
        "last_request_headers",
        "finding_history",
        "historical_findings",
        "prior_findings",
        "previous_findings",
        "findings",
        "vulnerability_history",
    ):
        value = _get(endpoint, key)
        if value not in (None, "", [], {}):
            context[key] = value
    return context


def build_readable_scan_plan(
    *,
    templates: list[dict] | tuple[dict, ...],
    endpoints: list[dict] | tuple[dict, ...],
    roles_context: dict | None = None,
    test_intensity: str | None = None,
    profile: object | None = None,
    selector: SelectionFilterEngine | None = None,
) -> dict[str, Any]:
    """Build a redacted, operator-readable plan before active scan execution."""
    template_list = [template for template in (templates or []) if isinstance(template, dict)]
    endpoint_list = [
        endpoint_selection_context(endpoint)
        for endpoint in (endpoints or [])
    ]
    effective_intensity = normalize_test_intensity(test_intensity, profile=profile)
    selector = selector or SelectionFilterEngine()
    summary = selector.summarize_context_aware_selection(
        template_list,
        endpoint_list,
        roles_context=roles_context,
    )
    outcomes = summary.get("selection_outcomes") or {}
    pair_count = int(outcomes.get("template_endpoint_pair_count") or (len(template_list) * len(endpoint_list)))
    selected_pair_count = int(outcomes.get("selected_pair_count") or 0)
    skipped_pair_count = int(outcomes.get("skipped_pair_count") or max(0, pair_count - selected_pair_count))
    selection = {
        "template_endpoint_pair_count": pair_count,
        "selected_pair_count": selected_pair_count,
        "skipped_pair_count": skipped_pair_count,
        "selected_template_count": int(outcomes.get("selected_template_count") or 0),
        "selected_endpoint_count": int(outcomes.get("selected_endpoint_count") or 0),
        "skip_reason_counts": _safe_int_mapping(outcomes.get("skip_reason_counts") or {}),
        "selection_starved": bool(outcomes.get("selection_starved")),
        "starved_template_count": int(outcomes.get("starved_template_count") or 0),
        "security_category_coverage_gap_count": int(outcomes.get("security_category_coverage_gap_count") or 0),
        "security_category_coverage_gaps": _safe_category_gaps(outcomes.get("security_category_coverage_gaps") or []),
        "pair_decision_count": int(outcomes.get("pair_decision_count") or 0),
        "pair_decision_report_truncated": bool(outcomes.get("pair_decision_report_truncated")),
        "pair_decisions": _safe_pair_decisions(outcomes.get("pair_decisions") or []),
    }

    controls = {
        "state_change_allowed": bool(getattr(profile, "allow_state_change", False)),
        "destructive_methods_allowed": bool(
            getattr(profile, "allow_destructive_methods", False)
            or getattr(profile, "allow_destructive", False)
        ),
        "max_active_requests_per_test": int(
            getattr(profile, "max_active_requests_per_test", settings.PENTEST_MAX_ACTIVE_REQUESTS_PER_TEST)
            or 0
        ),
    }
    context_inputs = _context_input_statuses(endpoint_list, roles_context)
    templates_summary = _templates_summary(outcomes.get("starved_templates") or [])
    readable_summary = _readable_summary(
        intensity=effective_intensity,
        selected_pair_count=selected_pair_count,
        pair_count=pair_count,
        skipped_pair_count=skipped_pair_count,
        context_status=str(summary.get("context_aware_selection_status") or "not_required"),
    )
    plan = {
        "schema_version": "scan_plan.v1",
        "test_intensity": effective_intensity,
        "requested": {
            "template_count": len(template_list),
            "endpoint_count": len(endpoint_list),
            "template_endpoint_pair_count": pair_count,
        },
        "selection": selection,
        "context": {
            "context_aware_selection": bool(summary.get("context_aware_selection")),
            "partial_context_aware_selection": bool(summary.get("partial_context_aware_selection")),
            "status": summary.get("context_aware_selection_status") or "not_required",
            "required_signals": list(summary.get("required_signals") or []),
            "available_signals": list(summary.get("available_signals") or []),
            "satisfied_signals": list(summary.get("satisfied_signals") or []),
            "missing_signals": list(summary.get("missing_signals") or []),
            "signal_gaps": _safe_context_signal_gaps(summary.get("context_signal_gaps") or []),
        },
        "context_inputs": context_inputs,
        "coverage_targets": _coverage_target_summary(
            templates=template_list,
            endpoints=endpoint_list,
            selection_outcomes=outcomes,
            roles_context=roles_context,
        ),
        "controls": controls,
        "templates": templates_summary,
        "readable_summary": readable_summary,
    }
    redacted_plan = Redactor.redact_json(plan)
    if not isinstance(redacted_plan, dict):
        return plan
    redacted_plan["context_inputs"] = context_inputs
    if isinstance(redacted_plan.get("context"), dict):
        redacted_plan["context"] = plan["context"]
    redacted_plan["coverage_targets"] = plan["coverage_targets"]
    return finalize_scan_plan_hash(redacted_plan)


def finalize_scan_plan_hash(scan_plan: dict[str, Any]) -> dict[str, Any]:
    """Attach the deterministic scan plan hash after all execution metadata is present."""
    scan_plan["hash_algorithm"] = "sha256"
    scan_plan["scan_plan_hash"] = scan_plan_digest(scan_plan)
    return scan_plan


def scan_plan_digest(scan_plan: dict[str, Any]) -> str:
    """Return a deterministic digest over the redacted scan plan contract."""
    canonical = {
        key: value
        for key, value in (scan_plan or {}).items()
        if key not in _SCAN_PLAN_DIGEST_IGNORED_KEYS
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def verify_scan_plan_integrity(scan_plan: dict[str, Any]) -> dict[str, Any]:
    expected_hash = str((scan_plan or {}).get("scan_plan_hash") or "")
    hash_algorithm = str((scan_plan or {}).get("hash_algorithm") or "").lower()
    actual_hash = scan_plan_digest(scan_plan or {})
    verified = bool(
        expected_hash
        and hash_algorithm == "sha256"
        and hmac.compare_digest(expected_hash, actual_hash)
    )
    return {
        "verified": verified,
        "status": "VERIFIED" if verified else "MISMATCH",
        "hash_algorithm": hash_algorithm or None,
        "expected_hash": expected_hash or None,
        "actual_hash": actual_hash,
    }


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _safe_int_mapping(value: dict) -> dict[str, int]:
    result = {}
    for key, count in (value or {}).items():
        try:
            result[str(key)] = int(count or 0)
        except (TypeError, ValueError):
            result[str(key)] = 0
    return result


def _safe_category_gaps(gaps: list[dict]) -> list[dict]:
    safe_gaps = []
    for gap in gaps[:25]:
        if not isinstance(gap, dict):
            continue
        safe_gaps.append(
            {
                "security_category": Redactor.redact_text(str(gap.get("security_category") or "uncategorized"))[:80],
                "template_count": int(gap.get("template_count") or 0),
                "starved_template_count": int(gap.get("starved_template_count") or 0),
                "skip_reason_counts": _safe_int_mapping(gap.get("skip_reason_counts") or {}),
            }
        )
    return safe_gaps


def _safe_context_signal_gaps(gaps: list[dict]) -> list[dict]:
    safe_gaps = []
    for gap in gaps[:25]:
        if not isinstance(gap, dict):
            continue
        safe_gaps.append(
            {
                "signal": Redactor.redact_text(str(gap.get("signal") or ""))[:80],
                "required_template_count": _safe_int(gap.get("required_template_count")),
                "available_context_count": _safe_int(gap.get("available_context_count")),
                "affected_template_count": _safe_int(gap.get("affected_template_count")),
                "affected_template_ids": _safe_redacted_list(gap.get("affected_template_ids"), limit=25),
                "recommended_inputs": _safe_redacted_list(gap.get("recommended_inputs"), limit=5, max_length=160),
            }
        )
    return safe_gaps


def _safe_redacted_list(value: Any, *, limit: int, max_length: int = 120) -> list[str]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value[:limit]:
        text = Redactor.redact_text(str(item or "").strip())[:max_length]
        if text and text != Redactor.REDACT_VALUE and text not in items:
            items.append(text)
    return items


def _safe_pair_decisions(decisions: list[dict]) -> list[dict]:
    safe_decisions = []
    for item in decisions[:500]:
        if not isinstance(item, dict):
            continue
        safe_decisions.append(
            {
                "template_index": _safe_int(item.get("template_index")),
                "template_id": Redactor.redact_text(str(item.get("template_id") or ""))[:120],
                "endpoint_index": _safe_int(item.get("endpoint_index")),
                "endpoint_id": Redactor.redact_text(str(item.get("endpoint_id") or ""))[:120],
                "security_category": Redactor.redact_text(str(item.get("security_category") or "uncategorized"))[:80],
                "selected": bool(item.get("selected")),
                "reason": Redactor.redact_text(str(item.get("reason") or "selection_filter_mismatch"))[:120],
                "extracted_variable_names": _safe_extracted_variable_names(item.get("extracted_variable_names")),
            }
        )
    return safe_decisions


def _safe_extracted_variable_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names = []
    for item in value:
        name = Redactor.redact_text(str(item or "").strip())[:120]
        if name and name != Redactor.REDACT_VALUE and name not in names:
            names.append(name)
    return sorted(names)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _templates_summary(starved_templates: list[dict]) -> list[dict]:
    templates = []
    for item in starved_templates[:25]:
        if not isinstance(item, dict):
            continue
        templates.append(
            {
                "template_index": int(item.get("template_index") or 0),
                "template_id": Redactor.redact_text(str(item.get("template_id") or ""))[:120],
                "security_category": Redactor.redact_text(str(item.get("security_category") or "uncategorized"))[:80],
                "required_signals": list(item.get("required_signals") or []),
                "selected_endpoint_count": int(item.get("selected_endpoint_count") or 0),
                "skipped_endpoint_count": int(item.get("skipped_endpoint_count") or 0),
                "skip_reason_counts": _safe_int_mapping(item.get("skip_reason_counts") or {}),
            }
        )
    return templates


def _readable_summary(
    *,
    intensity: str,
    selected_pair_count: int,
    pair_count: int,
    skipped_pair_count: int,
    context_status: str,
) -> list[str]:
    summary = [
        f"{intensity.title()} scan plan: {selected_pair_count} of {pair_count} template/endpoint pairs selected."
    ]
    if skipped_pair_count:
        summary.append(f"{skipped_pair_count} pair(s) will be skipped by context-aware selection.")
    summary.append(f"Context-aware selection status: {context_status}.")
    return summary


def _context_input_statuses(endpoints: list[dict], roles_context: dict | None) -> dict[str, str]:
    return {
        "method": _status(any(endpoint.get("method") for endpoint in endpoints)),
        "auth": _status(any(endpoint.get("auth_types_found") for endpoint in endpoints)),
        "schema": _status(any(_has_schema(endpoint) for endpoint in endpoints)),
        "parameters": _status(any(_has_parameters(endpoint) for endpoint in endpoints)),
        "sensitive_fields": _status(any(_has_sensitive_fields(endpoint) for endpoint in endpoints)),
        "roles": _status(bool(roles_context)),
        "response_shape": _status(any(_has_response_shape(endpoint) for endpoint in endpoints)),
        "historical_findings": _status(any(_has_historical_findings(endpoint) for endpoint in endpoints)),
    }


def _coverage_target_summary(
    *,
    templates: list[dict],
    endpoints: list[dict],
    selection_outcomes: dict,
    roles_context: dict | None,
) -> dict[str, dict[str, Any]]:
    requested_categories = _requested_security_categories(templates, selection_outcomes)
    authorization_endpoint_signals = [_authorization_endpoint_signals(endpoint) for endpoint in endpoints]
    llm_endpoint_signals = [_llm_endpoint_signals(endpoint) for endpoint in endpoints]
    business_endpoint_signals = [_business_flow_endpoint_signals(endpoint) for endpoint in endpoints]
    role_count = len(roles_context or {})
    identity_context = _authorization_identity_context(roles_context)
    authorization_summary = _target_surface_summary(
        template_requested="authorization" in requested_categories,
        endpoint_signals=authorization_endpoint_signals,
        global_signals={"role_context"} if role_count else set(),
        readiness=_authorization_readiness(
            template_requested="authorization" in requested_categories,
            endpoint_signals=authorization_endpoint_signals,
            identity_context=identity_context,
        ),
    )
    authorization_summary["identity_context"] = identity_context
    business_logic_summary = _target_surface_summary(
        template_requested="business_logic" in requested_categories,
        endpoint_signals=business_endpoint_signals,
        readiness=_business_logic_readiness(
            template_requested="business_logic" in requested_categories,
            endpoint_signals=business_endpoint_signals,
        ),
    )
    business_logic_summary["active_test_families"] = _scan_plan_business_active_test_families(
        templates=templates,
        endpoints=endpoints,
    )
    llm_api_summary = _target_surface_summary(
        template_requested="llm" in requested_categories,
        endpoint_signals=llm_endpoint_signals,
        readiness=_llm_readiness(
            template_requested="llm" in requested_categories,
            endpoint_signals=llm_endpoint_signals,
        ),
    )
    llm_active_families = _scan_plan_llm_active_test_families(
        templates=templates,
        endpoints=endpoints,
    )
    if llm_active_families:
        llm_api_summary["active_test_families"] = llm_active_families
    return {
        "authorization": authorization_summary,
        "llm_api": llm_api_summary,
        "business_logic": business_logic_summary,
    }


def _scan_plan_business_active_test_families(*, templates: list[dict], endpoints: list[dict]) -> dict[str, Any]:
    families = business_abuse_family_coverage(templates=templates, endpoints=endpoints)
    workflow = families.get("workflow_bypass")
    if isinstance(workflow, dict) and isinstance(workflow.get("signals"), list):
        workflow["signals"] = [signal for signal in workflow["signals"] if signal != "checkout"]
    return families


def _scan_plan_llm_active_test_families(*, templates: list[dict], endpoints: list[dict]) -> dict[str, Any]:
    template_counts = {family: 0 for family in _LLM_ACTIVE_FAMILY_ORDER}
    for template in templates:
        family = _llm_active_template_family(template)
        if family:
            template_counts[family] += 1

    if not any(template_counts.values()):
        return {}

    endpoint_signal_sets = [_llm_endpoint_active_signals(endpoint) for endpoint in endpoints]
    coverage: dict[str, Any] = {}
    for family in _LLM_ACTIVE_FAMILY_ORDER:
        config = _LLM_ACTIVE_FAMILY_CONFIG[family]
        required_signals = set(config["endpoint_required_signals"])
        reported_signals = set(config["reported_signals"])
        matching_endpoint_signals = [
            signals
            for signals in endpoint_signal_sets
            if required_signals <= signals
        ]
        observed_signals = sorted(
            {
                signal
                for signals in endpoint_signal_sets
                for signal in signals
                if signal in reported_signals
            }
        )
        template_count = template_counts[family]
        endpoint_signal_count = len(matching_endpoint_signals)
        ready = template_count > 0 and endpoint_signal_count > 0
        coverage[family] = {
            "template_count": template_count,
            "endpoint_signal_count": endpoint_signal_count,
            "ready": ready,
            "status": (
                "ready"
                if ready
                else "missing_template"
                if template_count == 0
                else "missing_endpoint_context"
            ),
            "signals": observed_signals,
        }
    return coverage


def _llm_active_template_family(template: dict) -> str | None:
    if not isinstance(template, dict) or not isinstance(template.get("active_llm"), dict):
        return None

    text = _llm_template_text(template)
    required_evidence = _llm_template_required_evidence(template)
    if (
        "untrusted_context_sha256" in required_evidence
        and "tool_invocation_sha256" in required_evidence
    ):
        return "tool_chain_injection"
    if "untrusted_context_sha256" in required_evidence or "indirect" in text:
        return "indirect_prompt_injection"
    if "retrieval_context_sha256" in required_evidence or "rag" in text:
        return "rag_exfiltration"
    if "tool_invocation_sha256" in required_evidence:
        if "privilege" in text or "escalat" in text:
            return "privilege_escalating_tool_invocation"
        return "dangerous_tool_invocation"
    if "prompt" in text or "system-prompt" in text or "system_prompt" in text:
        return "prompt_injection"
    return None


def _llm_template_text(template: dict) -> str:
    values: list[Any] = [
        template.get("id"),
        template.get("name"),
        template.get("description"),
    ]
    info = template.get("info")
    if isinstance(info, dict):
        values.extend([info.get("name"), info.get("description")])
        tags = info.get("tags")
        if isinstance(tags, list):
            values.extend(tags)
        elif isinstance(tags, str):
            values.append(tags)
    return " ".join(str(value or "") for value in values).lower().replace("_", "-")


def _llm_template_required_evidence(template: dict) -> set[str]:
    active_llm = template.get("active_llm")
    if not isinstance(active_llm, dict):
        return set()
    deterministic = active_llm.get("deterministic_evidence")
    if not isinstance(deterministic, dict):
        return set()
    required = deterministic.get("required")
    if not isinstance(required, list):
        return set()
    return {str(item or "").strip() for item in required if str(item or "").strip()}


def _requested_security_categories(templates: list[dict], selection_outcomes: dict) -> set[str]:
    categories: set[str] = set()
    for item in selection_outcomes.get("security_category_coverage") or []:
        if isinstance(item, dict) and item.get("security_category"):
            categories.add(str(item["security_category"]))
    for template in templates:
        categories.add(_template_security_category(template))
    return {category for category in categories if category}


def _target_surface_summary(
    *,
    template_requested: bool,
    endpoint_signals: list[set[str]],
    global_signals: set[str] | None = None,
    readiness: dict[str, bool] | None = None,
) -> dict[str, Any]:
    non_empty_signals = [signals for signals in endpoint_signals if signals]
    all_signals = sorted(
        {
            signal
            for signals in non_empty_signals
            for signal in signals
        }
        | set(global_signals or set())
    )
    signal_available = bool(non_empty_signals or global_signals)
    if template_requested and signal_available:
        status = "available"
    elif template_requested:
        status = "gap"
    elif signal_available:
        status = "discovered"
    else:
        status = "not_requested"
    summary = {
        "template_requested": bool(template_requested),
        "template_covered": bool(template_requested and non_empty_signals),
        "endpoint_signal_count": len(non_empty_signals),
        "status": status,
        "signals": all_signals,
    }
    if readiness:
        summary["readiness"] = readiness
    return summary


def _llm_readiness(*, template_requested: bool, endpoint_signals: list[set[str]]) -> dict[str, bool]:
    signals = _combined_endpoint_signals(endpoint_signals)
    prompt_context_ready = "body_key" in signals
    tool_context_ready = "tool_context" in signals
    return {
        "prompt_context_ready": prompt_context_ready,
        "tool_context_ready": tool_context_ready,
        "tool_abuse_testable": bool(template_requested and prompt_context_ready and tool_context_ready),
    }


def _business_logic_readiness(*, template_requested: bool, endpoint_signals: list[set[str]]) -> dict[str, bool]:
    signals = _combined_endpoint_signals(endpoint_signals)
    workflow_context_ready = "workflow_path" in signals
    state_change_context_ready = "state_changing_method" in signals
    private_identifier_context_ready = "private_identifier" in signals
    return {
        "workflow_context_ready": workflow_context_ready,
        "state_change_context_ready": state_change_context_ready,
        "private_identifier_context_ready": private_identifier_context_ready,
        "workflow_abuse_testable": bool(
            template_requested
            and workflow_context_ready
            and state_change_context_ready
            and private_identifier_context_ready
        ),
    }


def _authorization_identity_context(roles_context: dict | None) -> dict[str, Any]:
    role_keys = _safe_role_keys(roles_context)
    privileged_count = len([role for role in role_keys if role in _PRIVILEGED_ROLE_KEYS])
    low_privilege_count = len([role for role in role_keys if role in _LOW_PRIVILEGE_ROLE_KEYS])
    role_count = len(role_keys)
    return {
        "role_count": role_count,
        "multi_identity_ready": role_count >= 2,
        "privileged_role_present": privileged_count > 0,
        "low_privilege_role_present": low_privilege_count > 0,
        "privilege_boundary_pair_count": privileged_count * low_privilege_count,
    }


def _authorization_readiness(
    *,
    template_requested: bool,
    endpoint_signals: list[set[str]],
    identity_context: dict[str, Any],
) -> dict[str, bool]:
    signals = _combined_endpoint_signals(endpoint_signals)
    auth_context_ready = "auth_context" in signals
    private_identifier_context_ready = "private_identifier" in signals
    role_context_ready = bool(identity_context.get("multi_identity_ready"))
    privilege_boundary_ready = int(identity_context.get("privilege_boundary_pair_count") or 0) > 0
    return {
        "auth_context_ready": auth_context_ready,
        "private_identifier_context_ready": private_identifier_context_ready,
        "role_context_ready": role_context_ready,
        "bola_replay_testable": bool(
            template_requested
            and auth_context_ready
            and private_identifier_context_ready
            and role_context_ready
        ),
        "bfla_replay_testable": bool(
            template_requested
            and auth_context_ready
            and role_context_ready
            and privilege_boundary_ready
        ),
    }


def _safe_role_keys(roles_context: dict | None) -> list[str]:
    if not isinstance(roles_context, dict):
        return []
    keys = []
    for raw_key in roles_context:
        key = str(raw_key or "").split(".")[-1].strip().upper().replace("-", "_")
        if key:
            keys.append(key)
    return sorted(set(keys))


def _combined_endpoint_signals(endpoint_signals: list[set[str]]) -> set[str]:
    return {
        signal
        for signals in endpoint_signals
        for signal in signals
    }


def _template_security_category(template: dict) -> str:
    candidates: list[Any] = []
    for key in ("security_category", "category", "type", "test_category"):
        value = template.get(key) if isinstance(template, dict) else None
        if value:
            candidates.append(value)
    info = template.get("info") if isinstance(template, dict) else None
    if isinstance(info, dict):
        for key in ("security_category", "category", "type"):
            if info.get(key):
                candidates.append(info[key])
        tags = info.get("tags")
        if isinstance(tags, str):
            candidates.extend(item.strip() for item in tags.split(",") if item.strip())
        elif isinstance(tags, list):
            candidates.extend(tags)

    for candidate in candidates:
        normalized = str(candidate or "").strip().lower().replace("-", "_").replace(" ", "_")
        if "llm" in normalized or "prompt" in normalized or "tool_output" in normalized:
            return "llm"
        if "business_logic" in normalized or "workflow" in normalized or "sequence" in normalized:
            return "business_logic"
        if "authorization" in normalized or "authz" in normalized or "bola" in normalized or "bfla" in normalized:
            return "authorization"
    return ""


def _authorization_endpoint_signals(endpoint: dict) -> set[str]:
    signals: set[str] = set()
    if endpoint.get("auth_types_found"):
        signals.add("auth_context")
    try:
        if int(endpoint.get("private_variable_count") or 0) > 0:
            signals.add("private_identifier")
    except (TypeError, ValueError):
        pass
    if not signals and _has_private_identifier_context(endpoint):
        signals.add("private_identifier")
    if signals and str(endpoint.get("method") or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        signals.add("state_changing_method")
    return signals


def _has_private_identifier_context(endpoint: dict) -> bool:
    for key, _ in _json_items(endpoint.get("last_request_body")) + _query_items(endpoint):
        if _PRIVATE_PARAMETER_RE.search(str(key)):
            return True
    for key, _ in _json_items(endpoint.get("last_response_body")):
        if _PRIVATE_PARAMETER_RE.search(str(key)):
            return True
    path = str(endpoint.get("path") or "")
    if not path and endpoint.get("url"):
        path = urlparse(str(endpoint["url"])).path
    return any(
        segment
        for segment in path.split("/")
        if segment and segment not in {"api", "v1", "v2"} and re.search(r"\d", segment)
    )


def _llm_endpoint_signals(endpoint: dict) -> set[str]:
    signals: set[str] = set()
    path = str(endpoint.get("path") or "")
    url = str(endpoint.get("url") or "")
    if _LLM_PATH_RE.search(path) or _LLM_PATH_RE.search(urlparse(url).path if url else ""):
        signals.add("path_hint")
    if _has_any_key(endpoint.get("last_request_body"), _LLM_BODY_KEYS) or _has_any_key(
        endpoint.get("last_response_body"),
        _LLM_BODY_KEYS,
    ):
        signals.add("body_key")
    if _has_any_key(endpoint.get("last_request_body"), _TOOL_CONTEXT_KEYS) or _has_any_key(
        endpoint.get("last_response_body"),
        _TOOL_CONTEXT_KEYS,
    ):
        signals.add("tool_context")
    return signals


def _llm_endpoint_active_signals(endpoint: dict) -> set[str]:
    signals = set(_llm_endpoint_signals(endpoint))
    request_body = endpoint.get("last_request_body")
    response_body = endpoint.get("last_response_body")

    if _has_any_key(request_body, _RAG_CONTEXT_KEYS) or _has_any_key(response_body, _RAG_CONTEXT_KEYS):
        signals.add("retrieval_context")
        signals.add("untrusted_context")
    if _has_any_key(request_body, _TOOL_OUTPUT_CONTEXT_KEYS) or _has_any_key(response_body, _TOOL_OUTPUT_CONTEXT_KEYS):
        signals.add("tool_output_context")
        signals.add("tool_context")
        signals.add("untrusted_context")
    if _has_any_key(request_body, _TOOL_INVOCATION_CONTEXT_KEYS) or _has_any_key(response_body, _TOOL_INVOCATION_CONTEXT_KEYS):
        signals.add("tool_invocation_context")
        signals.add("tool_context")
    return signals


def _business_flow_endpoint_signals(endpoint: dict) -> set[str]:
    signals: set[str] = set()
    path = str(endpoint.get("path") or "")
    url = str(endpoint.get("url") or "")
    parsed_path = urlparse(url).path if url else ""
    if _BUSINESS_FLOW_PATH_RE.search(path) or _BUSINESS_FLOW_PATH_RE.search(parsed_path):
        signals.add("workflow_path")
    try:
        if int(endpoint.get("private_variable_count") or 0) > 0:
            signals.add("private_identifier")
    except (TypeError, ValueError):
        pass
    if signals and str(endpoint.get("method") or "GET").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        signals.add("state_changing_method")
    return signals


def _has_any_key(value: Any, keys: set[str]) -> bool:
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else {}
        except Exception:
            lowered = value.lower()
            return any(key in lowered for key in keys)
    if isinstance(value, dict):
        lowered_keys = {str(key).lower() for key in value}
        if lowered_keys & keys:
            return True
        return any(_has_any_key(child, keys) for child in value.values())
    if isinstance(value, list):
        return any(_has_any_key(child, keys) for child in value[:20])
    return False


def _status(available: bool) -> str:
    return "available" if available else "missing"


def _has_schema(endpoint: dict) -> bool:
    return any(endpoint.get(key) not in (None, "", [], {}) for key in ("request_schema", "response_schema", "schema_json"))


def _has_parameters(endpoint: dict) -> bool:
    if endpoint.get("parameters") not in (None, "", [], {}):
        return True
    if endpoint.get("last_query_string"):
        return True
    try:
        if int(endpoint.get("private_variable_count") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    for key, _ in _json_items(endpoint.get("last_request_body")) + _query_items(endpoint):
        if _PRIVATE_PARAMETER_RE.search(str(key)):
            return True
    path = str(endpoint.get("path") or "")
    return any(segment for segment in path.split("/") if segment and segment not in {"api", "v1", "v2"})


def _has_sensitive_fields(endpoint: dict) -> bool:
    explicit = endpoint.get("sensitive_fields")
    if isinstance(explicit, list) and explicit:
        return True
    for value in (
        endpoint.get("last_request_body"),
        endpoint.get("last_response_body"),
        endpoint.get("last_response_headers"),
        endpoint.get("last_request_headers"),
        endpoint.get("last_query_string"),
    ):
        if _SENSITIVE_FIELD_RE.search(_stringify(value)):
            return True
    if endpoint.get("url"):
        parsed = urlparse(str(endpoint.get("url")))
        return bool(_SENSITIVE_FIELD_RE.search(parsed.query or ""))
    return False


def _has_response_shape(endpoint: dict) -> bool:
    return bool(
        endpoint.get("response_schema")
        or endpoint.get("last_response_body")
        or endpoint.get("last_response_headers")
        or endpoint.get("last_response_code") is not None
    )


def _has_historical_findings(endpoint: dict) -> bool:
    return any(
        endpoint.get(key) not in (None, "", [], {})
        for key in (
            "finding_history",
            "historical_findings",
            "prior_findings",
            "previous_findings",
            "findings",
            "vulnerability_history",
        )
    )


def _json_items(value: Any) -> list[tuple[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value) if value else {}
        except Exception:
            return []
    items: list[tuple[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    walk(child)
                else:
                    items.append((str(key), child))
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return items


def _query_items(endpoint: dict) -> list[tuple[str, str]]:
    query_string = str(endpoint.get("last_query_string") or "").lstrip("?")
    if not query_string and endpoint.get("url"):
        query_string = urlparse(str(endpoint["url"])).query
    return [
        tuple(part.split("=", 1))
        for part in query_string.split("&")
        if "=" in part
    ]


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
