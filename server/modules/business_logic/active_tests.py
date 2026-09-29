"""Bounded active business-logic scenario generation."""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from server.modules.test_executor.scan_plan import normalize_test_intensity
from server.modules.test_executor.state_change_guard import StateChangeGuard
from server.modules.utils.redactor import Redactor

ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID = "ACTIVE_BUSINESS_LOGIC"

_COUPON_PATH_RE = re.compile(r"(coupon|discount|promo)", re.IGNORECASE)
_OTP_PATH_RE = re.compile(r"(otp|mfa|verify|verification)", re.IGNORECASE)
_RESOURCE_PATH_RE = re.compile(r"(search|list|export|report|bulk|page|orders?)", re.IGNORECASE)
_MONETARY_PATH_RE = re.compile(
    r"(checkout|payment|refund|transfer|payout|invoice|order|subscription|billing)",
    re.IGNORECASE,
)
_WORKFLOW_PATH_RE = re.compile(
    r"(cart|checkout|payment|refund|transfer|invoice|order|subscription|coupon|otp|mfa|verify)",
    re.IGNORECASE,
)
_SCENARIO_ABUSE_FAMILIES = {
    "coupon_replay": "coupon_abuse",
    "otp_throttle_probe": "otp_spam",
    "workflow_direct_entry": "workflow_bypass",
    "monetary_amount_boundary": "monetary_abuse",
    "resource_limit_boundary": "resource_exhaustion",
}


def build_active_business_logic_templates(
    endpoints: list[Any] | tuple[Any, ...],
    *,
    graph: Any | None = None,
    test_intensity: str | None = None,
) -> list[dict[str, Any]]:
    """Generate safe, bounded active abuse templates from endpoint and graph context."""
    intensity = normalize_test_intensity(test_intensity)
    templates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for endpoint in endpoints or []:
        context = _endpoint_context(endpoint)
        if not context["path"]:
            continue
        for template in _templates_for_endpoint(context, intensity=intensity, graph=graph):
            template_id = str(template["id"])
            if template_id in seen_ids:
                continue
            seen_ids.add(template_id)
            templates.append(template)
    return templates


def _templates_for_endpoint(context: dict[str, Any], *, intensity: str, graph: Any | None) -> list[dict[str, Any]]:
    path = str(context["path"])
    templates: list[dict[str, Any]] = []
    if _COUPON_PATH_RE.search(path):
        templates.append(
            _template(
                context,
                scenario_type="coupon_replay",
                severity="HIGH",
                description="Replay a canary coupon mutation to detect reusable discount abuse.",
                body_params={"coupon_code": "APISENTINEL-COUPON-REPLAY-CANARY"},
                max_requests=_max_requests(intensity, ceiling=2),
                allow_state_change=True,
                graph=graph,
            )
        )
    if _OTP_PATH_RE.search(path):
        templates.append(
            _template(
                context,
                scenario_type="otp_throttle_probe",
                severity="MEDIUM",
                description="Probe whether OTP or verification endpoints enforce throttling boundaries.",
                body_params={"otp": "000000", "verification_code": "000000"},
                max_requests=_max_requests(intensity, ceiling=2),
                allow_state_change=True,
                graph=graph,
            )
        )
    if _MONETARY_PATH_RE.search(path):
        templates.append(
            _template(
                context,
                scenario_type="monetary_amount_boundary",
                severity="HIGH",
                description=(
                    "Probe monetary amount, quantity, and currency boundaries with a bounded canary mutation."
                ),
                body_params={"amount": "0.01", "quantity": "1", "currency": "USD"},
                max_requests=1,
                allow_state_change=True,
                graph=graph,
            )
        )
    if _RESOURCE_PATH_RE.search(path):
        templates.append(
            _template(
                context,
                scenario_type="resource_limit_boundary",
                severity="LOW",
                description="Request a small boundary limit to detect weak resource-consumption controls.",
                query_params={"limit": "101", "page_size": "101"},
                max_requests=1,
                allow_state_change=not StateChangeGuard.is_safe_method(context["method"]),
                graph=graph,
            )
        )
    workflow_template = _workflow_direct_entry_template(context, graph=graph, intensity=intensity)
    if workflow_template is not None:
        templates.append(workflow_template)
    return templates


def _template(
    context: dict[str, Any],
    *,
    scenario_type: str,
    severity: str,
    description: str,
    max_requests: int,
    allow_state_change: bool,
    body_params: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
    graph_metadata: dict[str, Any] | None = None,
    graph: Any | None = None,
) -> dict[str, Any]:
    method = str(context["method"] or "GET").upper()
    abuse_family = _SCENARIO_ABUSE_FAMILIES.get(scenario_type, scenario_type)
    request_rule: dict[str, Any] = {
        "add_header": {
            "X-API-Sentinel-Scenario": scenario_type,
            "X-API-Sentinel-Safe-Probe": "true",
        }
    }
    if body_params:
        request_rule["modify_body_param"] = body_params
    if query_params:
        request_rule["add_query_param"] = query_params
    if method:
        request_rule["modify_method"] = method

    scenario = {
        "scenario_type": scenario_type,
        "abuse_family": abuse_family,
        "endpoint_id": Redactor.redact_text(str(context.get("id") or "")),
        "path": Redactor.redact_url(str(context["path"])),
        "safe_throttle": {
            "max_requests": max_requests,
            "per_endpoint": True,
            "honor_retry_after": True,
        },
        "deterministic_evidence": _deterministic_evidence_metadata(),
        "flow_mapping": _flow_mapping(context, graph=graph, graph_metadata=graph_metadata),
    }
    if graph_metadata:
        scenario.update(graph_metadata)

    return {
        "id": _template_id(scenario_type, context),
        "security_category": "business_logic",
        "active_business_logic": scenario,
        "info": {
            "name": f"Active business logic {scenario_type.replace('_', ' ')}",
            "severity": severity,
            "category": {"name": "Business Logic"},
            "description": description,
            "tags": ["business_logic", abuse_family, scenario_type],
        },
        "api_selection_filters": {
            "method": {"eq": method},
        },
        "execute": {
            "type": "single",
            "allow_state_change": bool(allow_state_change),
            "allow_destructive_methods": False,
            "max_active_requests_per_test": max_requests,
            "requests": [{"req": [request_rule]}],
        },
        "validate": {
            "response_code": {"gte": 200, "lt": 400},
        },
    }


def _workflow_direct_entry_template(
    context: dict[str, Any],
    *,
    graph: Any | None,
    intensity: str,
) -> dict[str, Any] | None:
    if graph is None:
        return None
    path = Redactor.redact_url(str(context["path"]))
    edges = getattr(graph, "edges_json", None) or []
    predecessors = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        to_path = Redactor.redact_url(str(edge.get("to") or ""))
        if to_path != path:
            continue
        from_path = Redactor.redact_url(str(edge.get("from") or ""))
        if from_path:
            predecessors.append(from_path)
    if not predecessors or not _WORKFLOW_PATH_RE.search(path):
        return None
    return _template(
        context,
        scenario_type="workflow_direct_entry",
        severity="HIGH",
        description="Attempt direct entry into a stateful workflow step without learned predecessors.",
        max_requests=1 if intensity == "safe" else _max_requests(intensity, ceiling=2),
        allow_state_change=False,
        graph_metadata={
            "graph_version": int(getattr(graph, "version", 0) or 0),
            "expected_predecessors": sorted(set(predecessors))[:10],
            "expected_predecessor_count": len(set(predecessors)),
        },
        graph=graph,
    )


def _endpoint_context(endpoint: Any) -> dict[str, Any]:
    method = str(_get(endpoint, "method") or "GET").upper()
    protocol = _get(endpoint, "protocol") or "https"
    host = _get(endpoint, "host") or ""
    path = str(_get(endpoint, "path") or "/")
    url = _get(endpoint, "url")
    if not url and host:
        url = f"{protocol}://{host}{path}"
    if url and not path:
        path = urlparse(str(url)).path or "/"
    return {
        "id": _get(endpoint, "id"),
        "method": method,
        "path": Redactor.redact_url(path),
        "url": Redactor.redact_url(str(url or path)),
        "is_sensitive": bool(_get(endpoint, "is_sensitive")),
        "private_variable_count": _safe_int(_get(endpoint, "private_variable_count")),
    }


def _max_requests(intensity: str, *, ceiling: int) -> int:
    requested = {"safe": 1, "standard": 2, "aggressive": 3}.get(intensity, 2)
    return max(1, min(ceiling, requested))


def _deterministic_evidence_metadata() -> dict[str, Any]:
    return {
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
    }


def _flow_mapping(
    context: dict[str, Any],
    *,
    graph: Any | None,
    graph_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    node_path = Redactor.redact_url(str(context["path"]))
    mapping: dict[str, Any] = {
        "graph_version": int(getattr(graph, "version", 0) or 0) if graph is not None else 0,
        "node_path": node_path,
        "sensitive_flow": False,
        "sensitive_signals": [],
    }
    if graph_metadata:
        for key in ("expected_predecessors", "expected_predecessor_count"):
            if key in graph_metadata:
                mapping[key] = graph_metadata[key]

    signals: set[str] = set()
    if context.get("is_sensitive"):
        signals.add("endpoint_marked_sensitive")
    if _safe_int(context.get("private_variable_count")) > 0:
        signals.add("private_variables_present")

    node = _graph_node_for_path(graph, node_path)
    if node is not None:
        mapping["node_observed"] = True
        if any(bool(node.get(key)) for key in ("sensitive_flow", "is_sensitive", "sensitive")):
            signals.add("graph_node_marked_sensitive")
        flow_id = node.get("flow_id") or node.get("flow")
        if flow_id:
            mapping["flow_id"] = Redactor.redact_text(str(flow_id))
    else:
        mapping["node_observed"] = False

    mapping["sensitive_flow"] = bool(signals)
    mapping["sensitive_signals"] = sorted(signals)
    return mapping


def _graph_node_for_path(graph: Any | None, path: str) -> dict[str, Any] | None:
    if graph is None:
        return None
    for node in getattr(graph, "nodes_json", None) or []:
        if not isinstance(node, dict):
            continue
        node_path = Redactor.redact_url(str(node.get("path") or ""))
        if node_path == path:
            return node
    return None


def _template_id(scenario_type: str, context: dict[str, Any]) -> str:
    material = f"{scenario_type}:{context.get('id')}:{context.get('method')}:{context.get('path')}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    return f"business-logic-{scenario_type.replace('_', '-')}-{digest}"


def _get(obj: Any, field: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(field)
    return getattr(obj, field, None)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
