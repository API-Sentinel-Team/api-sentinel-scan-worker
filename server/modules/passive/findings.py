from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import BusinessLogicViolation
from server.modules.test_executor.evidence import finalize_finding_evidence
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

_PASSIVE_ATTACK_TYPES = {
    "SQL Injection": "SQL_INJECTION",
    "Blind SQLi": "SQL_INJECTION",
    "XSS": "XSS",
    "Path Traversal": "PATH_TRAVERSAL",
    "Command Injection": "COMMAND_INJECTION",
    "Code Injection": "CODE_INJECTION",
    "LDAP Injection": "LDAP_INJECTION",
    "SSRF": "SSRF",
    "Sensitive File Access": "SENSITIVE_FILE_ACCESS",
    "SQL_INJECTION": "SQL_INJECTION",
    "COMMAND_INJECTION": "COMMAND_INJECTION",
}
_SENSITIVE_ENTITY_SEVERITY = {
    "CREDIT_CARD": "HIGH",
    "SSN": "HIGH",
    "JWT": "HIGH",
    "EMAIL": "MEDIUM",
    "PHONE": "MEDIUM",
}


def _text(value: Any, *, default: str = "") -> str:
    text = str(value or default).strip()
    return text or default


def _truncate(value: Any, limit: int) -> str:
    return _text(value)[:limit]


def _status_code(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_method(value: Any) -> str:
    return _truncate(_text(value, default="GET").upper(), 10)


def _slug(value: Any) -> str:
    return _text(value, default="unknown").lower().replace("_", "-").replace(" ", "-")[:64]


def _passive_scope_validation(url: str) -> dict[str, Any]:
    safe_url = Redactor.redact_url(_text(url, default="/"))
    return {
        "validated": True,
        "policy": "passive_traffic_scope",
        "scope": "captured_account_traffic",
        "target": safe_url,
        "evidence_url": safe_url,
    }


def should_promote_passive_attack(category: str, severity: str, response_code: Any) -> bool:
    """Only turn passive attack attempts into vulnerabilities when the response suggests exposure."""

    normalized_category = _PASSIVE_ATTACK_TYPES.get(_text(category))
    if not normalized_category:
        return False
    code = _status_code(response_code)
    if 200 <= code <= 399:
        return True
    if 500 <= code <= 599 and _text(severity).upper() in {"HIGH", "CRITICAL"}:
        return True
    return False


def _confidence_from_response(response_code: Any) -> str:
    code = _status_code(response_code)
    if 200 <= code <= 299:
        return "HIGH"
    if 300 <= code <= 399:
        return "MEDIUM"
    return "MEDIUM"


def build_passive_attack_vulnerability_data(
    *,
    account_id: int,
    category: str,
    severity: str,
    response_code: Any,
    url: str,
    method: str,
    endpoint_id: str | None = None,
    source: str = "passive_traffic",
    actor: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    normalized_type = _PASSIVE_ATTACK_TYPES.get(_text(category))
    if not normalized_type or not should_promote_passive_attack(category, severity, response_code):
        return None

    safe_url = Redactor.redact_url(_text(url, default="/"))
    safe_evidence = Redactor.redact_json(evidence or {})
    method_value = _safe_method(method)
    confidence = _confidence_from_response(response_code)
    remediation = (
        "Validate and encode untrusted input server-side, use parameterized APIs where applicable, "
        "and add negative tests for the observed payload class."
    )
    return {
        "account_id": account_id,
        "template_id": _truncate(f"passive-{_slug(normalized_type)}", 100),
        "endpoint_id": endpoint_id,
        "url": safe_url,
        "method": method_value,
        "severity": _text(severity, default="MEDIUM").upper(),
        "type": _truncate(f"PASSIVE:{normalized_type}", 100),
        "description": (
            f"Passive traffic observed a {category} payload that received HTTP {response_code}. "
            "This suggests the endpoint may be vulnerable or missing defensive handling."
        ),
        "status": "OPEN",
        "confidence": confidence,
        "remediation": remediation,
        "evidence": finalize_finding_evidence({
            "engine": "passive_traffic",
            "source": source,
            "category": category,
            "actor": _truncate(actor, 120),
            "response_code": _status_code(response_code),
            "url": safe_url,
            "method": method_value,
            "details": safe_evidence,
        },
            method=method_value,
            url=safe_url,
            matched_rule={
                "category": category,
                "detector": "passive_traffic",
            },
            received_response={"status_code": _status_code(response_code)},
            similarity={
                "source": "passive_response_signal",
                "confidence": confidence,
            },
            remediation=remediation,
        ),
    }


async def persist_passive_attack_signal(
    db: AsyncSession,
    *,
    account_id: int,
    category: str,
    severity: str,
    response_code: Any,
    url: str,
    method: str,
    endpoint_id: str | None = None,
    source: str = "passive_traffic",
    actor: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    vulnerability_data = build_passive_attack_vulnerability_data(
        account_id=account_id,
        category=category,
        severity=severity,
        response_code=response_code,
        url=url,
        method=method,
        endpoint_id=endpoint_id,
        source=source,
        actor=actor,
        evidence=evidence,
    )
    if vulnerability_data is None:
        return None
    vulnerability, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
    return {
        "id": vulnerability.id,
        "created": created,
        "fingerprint": fingerprint,
        "template_id": vulnerability.template_id,
        "severity": vulnerability.severity,
        "type": vulnerability.type,
        "occurrence_count": int(vulnerability.occurrence_count or 1),
    }


def build_sensitive_data_exposure_vulnerability_data(
    *,
    account_id: int,
    endpoint_id: str | None,
    entity_type: str,
    source: str,
    path: str | None = None,
    method: str | None = None,
) -> dict[str, Any]:
    entity = _text(entity_type, default="SENSITIVE_DATA").upper()
    location = _text(source, default="response").lower()
    severity = _SENSITIVE_ENTITY_SEVERITY.get(entity, "MEDIUM")
    method_value = _safe_method(method)
    safe_path = Redactor.redact_url(_text(path, default="/"))
    confidence = "HIGH" if location == "response" else "MEDIUM"
    remediation = (
        "Avoid returning sensitive data unless explicitly required, mask tokens and regulated identifiers, "
        "and enforce response-field allowlists per role."
    )
    return {
        "account_id": account_id,
        "template_id": _truncate(f"passive-sensitive-data-{_slug(entity)}-{location}", 100),
        "endpoint_id": endpoint_id,
        "url": safe_path,
        "method": method_value,
        "severity": severity,
        "type": _truncate(f"PASSIVE:SENSITIVE_DATA_EXPOSURE:{entity}", 100),
        "description": f"Passive traffic observed {entity} in the API {location}.",
        "status": "OPEN",
        "confidence": confidence,
        "remediation": remediation,
        "evidence": finalize_finding_evidence({
            "engine": "passive_traffic",
            "detector": "pii_scanner",
            "entity_type": entity,
            "source": location,
            "sample": Redactor.REDACT_VALUE,
            "path": safe_path,
            "method": method_value,
        },
            method=method_value,
            url=safe_path,
            matched_rule={
                "detector": "pii_scanner",
                "entity_type": entity,
            },
            received_response={
                "source": location,
                "entity_type": entity,
            },
            similarity={
                "source": "sensitive_entity_detector",
                "confidence": confidence,
            },
            remediation=remediation,
        ),
    }


async def persist_sensitive_data_exposure(
    db: AsyncSession,
    *,
    account_id: int,
    endpoint_id: str | None,
    entity_type: str,
    source: str,
    path: str | None = None,
    method: str | None = None,
) -> dict[str, Any]:
    vulnerability_data = build_sensitive_data_exposure_vulnerability_data(
        account_id=account_id,
        endpoint_id=endpoint_id,
        entity_type=entity_type,
        source=source,
        path=path,
        method=method,
    )
    vulnerability, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
    return {
        "id": vulnerability.id,
        "created": created,
        "fingerprint": fingerprint,
        "template_id": vulnerability.template_id,
        "severity": vulnerability.severity,
        "type": vulnerability.type,
        "occurrence_count": int(vulnerability.occurrence_count or 1),
    }


def build_business_logic_vulnerability_data(
    *,
    account_id: int,
    violation: BusinessLogicViolation,
) -> dict[str, Any]:
    from_path = (
        Redactor.redact_url(_text(violation.from_path))
        if violation.from_path
        else "direct_entry"
    )
    to_path = Redactor.redact_url(_text(violation.to_path, default="/"))
    violation_type = _text(violation.violation_type, default="FORBIDDEN_TRANSITION").upper()
    details = Redactor.redact_json(violation.details or {})
    remediation = (
        "Enforce server-side workflow state checks and require prerequisite actions before allowing "
        "state-sensitive operations."
    )
    if violation_type == "TOO_FAST_TRANSITION":
        template_id = "passive-business-logic-too-fast-transition"
        description = (
            f"Passive workflow graph observed an unusually fast transition {from_path} -> {to_path}."
        )
    elif violation_type == "MISSING_PREREQUISITE":
        template_id = "passive-business-logic-missing-prerequisite"
        description = (
            f"Passive workflow graph observed direct entry to {to_path} without a learned prerequisite step."
        )
    else:
        template_id = "passive-business-logic-transition"
        description = f"Passive workflow graph observed an unexpected transition {from_path} -> {to_path}."
    return {
        "account_id": account_id,
        "template_id": template_id,
        "endpoint_id": None,
        "url": to_path,
        "method": "GET",
        "severity": "HIGH",
        "type": _truncate(f"PASSIVE:BUSINESS_LOGIC:{violation_type}", 100),
        "description": description,
        "status": "OPEN",
        "confidence": "MEDIUM",
        "remediation": remediation,
        "evidence": finalize_finding_evidence({
            "engine": "passive_traffic",
            "detector": "business_logic_graph",
            "violation_id": violation.id,
            "actor_id": _truncate(violation.actor_id, 120),
            "from_path": from_path,
            "to_path": to_path,
            "violation_type": violation_type,
            "confidence": violation.confidence,
            "details": details,
            "scope_validation": _passive_scope_validation(to_path),
        },
            method="GET",
            url=to_path,
            matched_rule={
                "detector": "business_logic_graph",
                "violation_type": violation_type,
            },
            received_response={
                "transition": f"{from_path if violation.from_path else 'direct_entry'} -> {to_path}",
                "violation_type": violation_type,
            },
            similarity={
                "source": "business_logic_graph",
                "confidence": violation.confidence,
            },
            remediation=remediation,
        ),
    }


async def persist_business_logic_violation(
    db: AsyncSession,
    *,
    account_id: int,
    violation: BusinessLogicViolation,
) -> dict[str, Any]:
    vulnerability_data = build_business_logic_vulnerability_data(
        account_id=account_id,
        violation=violation,
    )
    vulnerability, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
    return {
        "id": vulnerability.id,
        "created": created,
        "fingerprint": fingerprint,
        "template_id": vulnerability.template_id,
        "severity": vulnerability.severity,
        "type": vulnerability.type,
        "occurrence_count": int(vulnerability.occurrence_count or 1),
    }
