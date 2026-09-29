from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.pentest.target_policy import (
    normalize_evidence_url,
    validate_pentest_target,
    validated_pentest_evidence_scope,
)
from server.modules.test_executor.evidence import finalize_finding_evidence
from server.modules.utils.finding_fingerprint import nuclei_fingerprint
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.lifecycle import vulnerability_confidence_from_evidence
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "UNKNOWN": "INFO",
}

_NUCLEI_URL_FIELDS = {"matched-at", "matched_at", "url", "uri", "host"}


def _safe_text(value: Any, *, default: str = "") -> str:
    text = str(value or default).strip()
    return text or default


def _truncate(value: Any, limit: int) -> str:
    text = _safe_text(value)
    return text[:limit]


def _severity(value: Any) -> str:
    return _SEVERITY_MAP.get(_safe_text(value, default="INFO").upper(), "INFO")


def _finding_info(finding: dict[str, Any]) -> dict[str, Any]:
    info = finding.get("info")
    return info if isinstance(info, dict) else {}


def _finding_url(finding: dict[str, Any], target: str) -> str:
    raw_url = _safe_text(
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("url")
        or finding.get("host"),
        default=target,
    )
    return normalize_evidence_url(raw_url, target_url=target)


def redact_nuclei_finding(
    finding: dict[str, Any],
    *,
    target: str,
    account_id: int | None = None,
    include_fingerprint: bool = False,
) -> dict[str, Any]:
    """Redact a Nuclei finding before storing or returning external-engine output."""
    safe = Redactor.redact_json(finding)
    if not isinstance(safe, dict):
        safe = {}
    for key in _NUCLEI_URL_FIELDS:
        if isinstance(safe.get(key), str):
            safe[key] = Redactor.redact_url(Redactor.redact_text(safe[key]))
    if include_fingerprint:
        safe["fingerprint"] = nuclei_fingerprint(finding, target=target, account_id=account_id)
    return safe


def build_nuclei_vulnerability_data(
    finding: dict[str, Any],
    *,
    account_id: int,
    target: str,
) -> dict[str, Any]:
    info = _finding_info(finding)
    template_id = _truncate(
        finding.get("template-id")
        or finding.get("template_id")
        or finding.get("id")
        or "nuclei-unknown",
        100,
    )
    severity = _severity(finding.get("severity") or info.get("severity"))
    name = _safe_text(finding.get("name") or info.get("name") or template_id)
    description = _safe_text(info.get("description") or finding.get("description") or name)
    evidence_url, scope_validation = validated_pentest_evidence_scope(_finding_url(finding, target), target_url=target)
    source_fingerprint = nuclei_fingerprint(finding, target=target, account_id=account_id)
    redacted_finding = redact_nuclei_finding(finding, target=target, account_id=account_id)
    method = _safe_text(finding.get("method"), default="GET").upper()[:10]
    remediation = info.get("remediation") or info.get("reference") or (
        "Review the Nuclei finding, verify the exposed behavior, and rerun the authenticated scan."
    )
    evidence = finalize_finding_evidence({
        "engine": "nuclei",
        "confirmation": {
            "confirmed": None,
            "status": "UNCONFIRMED",
            "reason": "external_engine_single_observation",
        },
        "source_fingerprint": source_fingerprint,
        "scope_validation": scope_validation,
        "target": Redactor.redact_url(target),
        "finding": redacted_finding,
    },
        method=method,
        url=evidence_url,
        matched_rule={
            "template_id": template_id,
            "name": name,
            "severity": severity,
        },
        received_response=_nuclei_received_response(finding),
        sent_request=_nuclei_sent_request(finding, evidence_url=evidence_url, method=method),
        similarity={
            "source": "nuclei_matcher",
            "confidence": "external_report",
        },
        remediation=str(remediation),
    )

    return {
        "account_id": account_id,
        "template_id": template_id,
        "endpoint_id": None,
        "url": Redactor.redact_url(evidence_url),
        "method": method,
        "severity": severity,
        "type": _truncate(f"NUCLEI:{template_id}", 100),
        "description": f"Nuclei finding: {description}",
        "status": "OPEN",
        "confidence": vulnerability_confidence_from_evidence(evidence),
        "remediation": evidence["remediation"],
        "evidence": evidence,
    }


def _nuclei_received_response(finding: dict[str, Any]) -> dict[str, Any]:
    response: dict[str, Any] = {}
    raw_status = finding.get("status-code") or finding.get("status_code") or finding.get("response-status-code")
    if raw_status is not None:
        try:
            code = int(raw_status)
            if code > 0:
                response["status_code"] = code
        except (TypeError, ValueError):
            pass

    body = finding.get("response") or finding.get("response-body") or finding.get("extracted-results")
    if body not in (None, "", []):
        response["body"] = body
    return response


def _nuclei_sent_request(finding: dict[str, Any], *, evidence_url: str, method: str) -> dict[str, Any] | None:
    """Extract a real sent_request from nuclei's curl-command or raw request field."""
    import re as _re

    curl_cmd = finding.get("curl-command") or finding.get("curl_command")
    if curl_cmd and isinstance(curl_cmd, str):
        m = _re.search(r"-X\s+(\w+)\s+['\"]?(https?://[^\s'\"]+)", curl_cmd)
        if m:
            return {"method": m.group(1).upper(), "url": m.group(2)}

    raw_request = finding.get("request")
    if raw_request and isinstance(raw_request, str):
        first_line = raw_request.split("\n", 1)[0].strip()
        parts = first_line.split(" ")
        if len(parts) >= 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return {"method": parts[0].upper(), "url": evidence_url}

    return None


async def persist_nuclei_findings(
    db: AsyncSession,
    *,
    account_id: int,
    target: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    created_count = 0
    merged_count = 0
    vulnerabilities: list[dict[str, Any]] = []

    validate_pentest_target(target)
    for finding in findings:
        vulnerability_data = build_nuclei_vulnerability_data(
            finding,
            account_id=account_id,
            target=target,
        )
        vulnerability, created, fingerprint = await create_or_merge_vulnerability(db, vulnerability_data)
        if created:
            created_count += 1
        else:
            merged_count += 1
        vulnerabilities.append(
            {
                "id": vulnerability.id,
                "created": created,
                "fingerprint": fingerprint,
                "source_fingerprint": vulnerability_data["evidence"]["source_fingerprint"],
                "template_id": vulnerability.template_id,
                "severity": vulnerability.severity,
                "url": vulnerability.url,
                "occurrence_count": int(vulnerability.occurrence_count or 1),
            }
        )

    return {
        "created_count": created_count,
        "merged_count": merged_count,
        "vulnerabilities": vulnerabilities,
    }
