"""Deterministic active-scan judge for LLM API security templates."""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from server.modules.llm.findings import detect_llm_api_signals
from server.modules.utils.redactor import Redactor

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_BASE_REQUIRED_EVIDENCE = [
    "body_content_persisted",
    "matched_text_persisted",
    "request_body_sha256",
    "response_body_sha256",
    "signal_count",
    "signal_types",
]
_RAG_CONTEXT_SURFACE_KEYS = {
    "retrieved_context",
    "retrieved_documents",
    "source_documents",
    "source_docs",
    "citations",
    "references",
    "chunks",
    "page_content",
}
_UNTRUSTED_CONTEXT_SURFACE_KEYS = _RAG_CONTEXT_SURFACE_KEYS | {
    "context_documents",
    "tool_output",
    "tool_outputs",
    "tool_result",
    "tool_results",
    "tool_observation",
    "observations",
}
_TOOL_OUTPUT_SURFACE_KEYS = {
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
_TOOL_INVOCATION_SURFACE_KEYS = _TOOL_OUTPUT_SURFACE_KEYS | {
    "arguments",
    "function",
    "function_call",
    "function_calls",
    "name",
    "tool_call",
    "tool_calls",
}
_SIGNAL_REQUIRED_EVIDENCE = {
    "LLM_RAG_EXFILTRATION": [
        "retrieval_context_sha256",
        "retrieval_context_surface_keys",
    ],
    "LLM_INDIRECT_PROMPT_INJECTION": [
        "untrusted_context_sha256",
        "untrusted_context_surface_keys",
    ],
    "LLM_TOOL_OUTPUT_SECRET_EXPOSURE": [
        "tool_context_sha256",
        "tool_context_surface_keys",
    ],
    "LLM_DANGEROUS_TOOL_INVOCATION": [
        "tool_invocation_sha256",
        "tool_invocation_surface_keys",
    ],
    "LLM_PRIVILEGE_ESCALATING_TOOL_INVOCATION": [
        "tool_invocation_sha256",
        "tool_invocation_surface_keys",
    ],
    "LLM_TOOL_CHAIN_PROMPT_INJECTION": [
        "untrusted_context_sha256",
        "untrusted_context_surface_keys",
        "tool_context_sha256",
        "tool_context_surface_keys",
        "tool_invocation_sha256",
        "tool_invocation_surface_keys",
    ],
}


def build_active_llm_judge_validation(
    *,
    path: str | None,
    method: str | None,
    request_body: Any,
    response_body: Any,
) -> dict[str, Any]:
    """Return minimized deterministic validation metadata for active LLM probes."""
    parsed_request = _parse_json_maybe(request_body)
    parsed_response = _parse_json_maybe(response_body)
    signals = detect_llm_api_signals(
        path=path,
        request_body=parsed_request,
        response_body=parsed_response,
    )
    summaries = [_signal_summary(signal) for signal in signals]
    signal_types = sorted({summary["signal_type"] for summary in summaries})
    context_evidence = _structured_context_evidence(parsed_response)
    required = _required_evidence_for_signal_types(signal_types)
    payload: dict[str, Any] = {
        "validator": "deterministic_active_llm_signal_judge",
        "surface": "active_llm_api",
        "path": Redactor.redact_url(str(path or "")),
        "method": str(method or "POST").upper()[:10],
        "signal_count": len(summaries),
        "signal_types": signal_types,
        "signals": summaries,
        "max_severity": _max_field(summaries, "severity", default="INFO"),
        "max_confidence": _max_field(summaries, "confidence", default="LOW"),
        "request_body_sha256": _safe_body_fingerprint(parsed_request),
        "response_body_sha256": _safe_body_fingerprint(parsed_response),
        "request_body_length": _safe_body_length(parsed_request),
        "response_body_length": _safe_body_length(parsed_response),
        **context_evidence,
        "body_content_persisted": False,
        "matched_text_persisted": False,
        "content_minimization": {
            "raw_request_body_persisted": False,
            "raw_response_body_persisted": False,
            "matched_text_persisted": False,
            "secret_values_persisted": False,
            "persisted_material": ["metadata", "sha256_digests", "lengths", "signal_summaries"],
        },
        "confirmed": False,
        "finding_status": "UNCONFIRMED",
        "promotion_decision": "no_signal_detected",
        "required_evidence": required,
        "confirmation_required": bool(summaries),
    }
    missing = [
        field
        for field in required
        if field not in payload or payload[field] in (None, "", [])
    ]
    payload["missing_evidence"] = missing
    payload["deterministic_evidence"] = not missing
    if summaries:
        payload["promotion_decision"] = (
            "promote_unconfirmed_finding" if payload["deterministic_evidence"] else "hold_for_review"
        )
    return Redactor.redact_json(payload)


def is_llm_security_template(template: dict[str, Any] | None) -> bool:
    if not isinstance(template, dict):
        return False
    values: list[Any] = [
        template.get("security_category"),
        template.get("category"),
        template.get("type"),
        template.get("id"),
    ]
    info = template.get("info")
    if isinstance(info, dict):
        values.extend([info.get("security_category"), info.get("category"), info.get("type"), info.get("tags")])
    text = json.dumps(values, sort_keys=True, default=str).lower()
    return "llm" in text or "prompt" in text or "rag" in text or "tool_invocation" in text


def _signal_summary(signal: dict[str, Any]) -> dict[str, Any]:
    matches = signal.get("matched_text")
    match_list = matches if isinstance(matches, list) else ([matches] if matches else [])
    summary: dict[str, Any] = {
        "signal_type": str(signal.get("signal_type") or "LLM_SECURITY"),
        "severity": str(signal.get("severity") or "HIGH").upper(),
        "confidence": str(signal.get("confidence") or "MEDIUM").upper(),
        "description": Redactor.redact_text(str(signal.get("description") or "LLM security signal detected.")),
        "matched_text_sha256": _safe_body_fingerprint(match_list),
        "matched_text_count": len(match_list),
        "matched_text_length": _safe_body_length(match_list),
        "matched_text_persisted": False,
    }
    for key in (
        "response_refused",
        "retrieval_context_present",
        "untrusted_context_present",
        "tool_context_present",
    ):
        if key in signal:
            summary[key] = bool(signal.get(key))
    if isinstance(signal.get("context_surface_keys"), list):
        summary["context_surface_keys"] = [
            Redactor.redact_text(str(item))[:80]
            for item in signal["context_surface_keys"][:20]
        ]
    exploit_chain = _safe_exploit_chain(signal.get("exploit_chain"))
    if exploit_chain:
        summary["exploit_chain"] = exploit_chain
    return summary


def _max_field(summaries: list[dict[str, Any]], field: str, *, default: str) -> str:
    if not summaries:
        return default
    if field == "confidence":
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    else:
        order = _SEVERITY_ORDER
    return max((str(item.get(field) or default).upper() for item in summaries), key=lambda item: order.get(item, 0))


def _safe_exploit_chain(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    allowed_keys = (
        "untrusted_tool_output_prompt_injection",
        "dangerous_tool_invocation",
        "privilege_escalating_tool_invocation",
    )
    return {key: bool(value.get(key)) for key in allowed_keys if key in value}


def _required_evidence_for_signal_types(signal_types: list[str]) -> list[str]:
    required = list(_BASE_REQUIRED_EVIDENCE)
    for signal_type in signal_types:
        required.extend(_SIGNAL_REQUIRED_EVIDENCE.get(signal_type, []))
    return _dedupe(required)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _structured_context_evidence(response_body: Any) -> dict[str, Any]:
    retrieval_keys, retrieval_text = _surface_text(response_body, _RAG_CONTEXT_SURFACE_KEYS)
    untrusted_keys, untrusted_text = _surface_text(response_body, _UNTRUSTED_CONTEXT_SURFACE_KEYS)
    tool_context_keys, tool_context_text = _surface_text(response_body, _TOOL_OUTPUT_SURFACE_KEYS)
    tool_invocation_keys, tool_invocation_text = _surface_text(response_body, _TOOL_INVOCATION_SURFACE_KEYS)
    return {
        "retrieval_context_present": bool(retrieval_keys),
        "retrieval_context_sha256": _safe_body_fingerprint(retrieval_text),
        "retrieval_context_surface_keys": retrieval_keys,
        "untrusted_context_present": bool(untrusted_keys),
        "untrusted_context_sha256": _safe_body_fingerprint(untrusted_text),
        "untrusted_context_surface_keys": untrusted_keys,
        "tool_context_present": bool(tool_context_keys),
        "tool_context_sha256": _safe_body_fingerprint(tool_context_text),
        "tool_context_surface_keys": tool_context_keys,
        "tool_invocation_present": bool(tool_invocation_keys),
        "tool_invocation_sha256": _safe_body_fingerprint(tool_invocation_text),
        "tool_invocation_surface_keys": tool_invocation_keys,
    }


def _surface_text(value: Any, surface_keys: set[str], *, limit: int = 20000) -> tuple[list[str], str]:
    hits: set[str] = set()
    parts: list[str] = []

    def walk(item: Any, *, in_surface: bool = False) -> None:
        if sum(len(part) for part in parts) > limit:
            return
        if isinstance(item, dict):
            for key, val in item.items():
                key_text = str(key).lower()
                nested_surface = in_surface or key_text in surface_keys
                if key_text in surface_keys:
                    hits.add(key_text)
                walk(val, in_surface=nested_surface)
            return
        if isinstance(item, list):
            for val in item[:20]:
                walk(val, in_surface=in_surface)
            return
        if in_surface and item is not None:
            parts.append(str(item))

    walk(value)
    return sorted(hits), " ".join(parts)[:limit]


def _safe_body_fingerprint(value: Any) -> str | None:
    text = Redactor.redact_text(_flatten_text(value))
    if not text:
        return None
    return sha256(text.encode("utf-8")).hexdigest()


def _safe_body_length(value: Any) -> int:
    return len(_flatten_text(value))


def _flatten_text(value: Any, *, limit: int = 20000) -> str:
    parts: list[str] = []

    def walk(item: Any) -> None:
        if sum(len(part) for part in parts) > limit:
            return
        if item is None:
            return
        if isinstance(item, dict):
            for key, val in item.items():
                parts.append(str(key))
                walk(val)
            return
        if isinstance(item, list):
            for val in item:
                walk(val)
            return
        parts.append(str(item))

    walk(value)
    return " ".join(parts)[:limit]


def _parse_json_maybe(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value
