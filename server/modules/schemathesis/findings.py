from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from hashlib import sha256
from typing import Any, Iterable
from urllib.parse import urljoin

from sqlalchemy.ext.asyncio import AsyncSession

from server.modules.pentest.target_policy import (
    validate_pentest_evidence_url,
    validate_pentest_target,
    validated_pentest_evidence_scope,
)
from server.modules.test_executor.evidence import finalize_finding_evidence
from server.modules.utils.redactor import Redactor
from server.modules.vulnerability_detector.lifecycle import vulnerability_confidence_from_evidence
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

MAX_JUNIT_XML_BYTES = 2 * 1024 * 1024
_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_PATH_RE = re.compile(r"(?<![:/])(/[A-Za-z0-9._~!$&'()*+,;=:@%/{}?-]+)")
_CHECK_HINTS = (
    ("ignored_auth", "ignored_auth"),
    ("unsupported_method", "unsupported_method"),
    ("negative_data_rejection", "negative_data_rejection"),
    ("response_schema_conformance", "response_schema_conformance"),
    ("not_a_server_error", "not_a_server_error"),
    ("server error", "not_a_server_error"),
    (" 5xx", "not_a_server_error"),
)


def _text(value: Any, *, default: str = "") -> str:
    text = str(value or default).strip()
    return text or default


def _truncate(value: Any, limit: int) -> str:
    return _text(value)[:limit]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _safe_parse_junit(junit_xml: str) -> ET.Element:
    if not isinstance(junit_xml, str) or not junit_xml.strip():
        raise ValueError("junit_xml: Schemathesis JUnit XML is required")
    if len(junit_xml.encode("utf-8")) > MAX_JUNIT_XML_BYTES:
        raise ValueError("junit_xml: report exceeds 2 MiB import limit")
    upper = junit_xml[:2048].upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError("junit_xml: DTD and entity declarations are not supported")
    try:
        return ET.fromstring(junit_xml)
    except ET.ParseError as exc:
        raise ValueError("junit_xml: invalid XML report") from exc


def _extract_method(blob: str) -> str:
    match = _METHOD_RE.search(blob)
    return (match.group(1).upper() if match else "GET")[:10]


def _extract_url(blob: str, target_url: str) -> str:
    url_match = _URL_RE.search(blob)
    if url_match:
        return url_match.group(0).rstrip(".,);]")
    path_match = _PATH_RE.search(blob)
    if path_match:
        return urljoin(target_url.rstrip("/") + "/", path_match.group(1).lstrip("/"))
    return target_url


_HTTP_REQUEST_LINE_RE = re.compile(
    r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP",
    re.IGNORECASE,
)
_HTTP_RESPONSE_STATUS_RE = re.compile(r"HTTP/[\d.]+\s+(\d{3})", re.IGNORECASE)


def _extract_schemathesis_request_response(
    text: str, *, base_url: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse method, URL, and response status from a Schemathesis failure/system-out block.

    Returns (sent_request, received_response_extras). Both may be empty dicts when
    the failure text contains no HTTP block.
    """
    req: dict[str, Any] = {}
    resp: dict[str, Any] = {}

    req_match = _HTTP_REQUEST_LINE_RE.search(text)
    if req_match:
        req["method"] = req_match.group(1).upper()
        raw_path = req_match.group(2)
        req["url"] = raw_path if raw_path.startswith("http") else (base_url.rstrip("/") + raw_path)

    resp_match = _HTTP_RESPONSE_STATUS_RE.search(text)
    if resp_match:
        resp["status_code"] = int(resp_match.group(1))

    return req, resp


def _check_name(classname: str, name: str, node: ET.Element) -> str:
    blob = f"{classname} {name} {node.get('type') or ''} {node.get('message') or ''} {node.text or ''}".lower()
    for needle, check in _CHECK_HINTS:
        if needle in blob:
            return check
    raw = _text(node.get("type") or node.get("message") or name, default="unknown")
    raw = raw.split(":")[0].split(".")[-1]
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return slug[:64] or "unknown"


def _severity(kind: str, check_name: str, message: str) -> str:
    blob = f"{check_name} {message}".lower()
    if kind == "error" or "not_a_server_error" in blob or "server error" in blob or "500" in blob:
        return "HIGH"
    if "ignored_auth" in blob or "unauthorized" in blob or "forbidden" in blob:
        return "HIGH"
    if "unsupported_method" in blob:
        return "MEDIUM"
    return "MEDIUM"


def _source_fingerprint(*, account_id: int, method: str, url: str, check_name: str, classname: str, name: str) -> str:
    payload = f"{account_id}|{method.upper()}|{url}|{check_name}|{classname}|{name}"
    return sha256(payload.encode("utf-8")).hexdigest()[:20]


def _iter_failures_from_root(root: ET.Element, *, target_url: str) -> Iterable[dict[str, Any]]:
    for testcase in root.iter():
        if _local_name(testcase.tag) != "testcase":
            continue
        classname = _text(testcase.get("classname"))
        name = _text(testcase.get("name"), default="schemathesis testcase")
        blob = f"{classname} {name}"
        method = _extract_method(blob)
        url = _extract_url(blob, target_url)
        for child in testcase:
            kind = _local_name(child.tag)
            if kind not in {"failure", "error"}:
                continue
            message = _text(child.get("message") or child.text, default=name)
            check_name = _check_name(classname, name, child)
            yield {
                "classname": classname,
                "name": name,
                "kind": kind,
                "method": method,
                "url": url,
                "check_name": check_name,
                "message": message,
                "failure_type": _text(child.get("type")),
                "failure_text": _text(child.text),
            }


def _count_testcases(root: ET.Element) -> int:
    return sum(1 for node in root.iter() if _local_name(node.tag) == "testcase")


def iter_schemathesis_junit_failures(junit_xml: str, *, target_url: str) -> Iterable[dict[str, Any]]:
    """Yield failure/error records from Schemathesis-compatible JUnit XML."""

    root = _safe_parse_junit(junit_xml)
    yield from _iter_failures_from_root(root, target_url=target_url)


def build_schemathesis_vulnerability_data(
    failure: dict[str, Any],
    *,
    account_id: int,
    target_url: str,
) -> dict[str, Any]:
    check_name = _truncate(failure.get("check_name") or "unknown", 64)
    method = _text(failure.get("method"), default="GET").upper()[:10]
    url, scope_validation = validated_pentest_evidence_scope(
        _text(failure.get("url"), default=target_url),
        target_url=target_url,
    )
    message = Redactor.redact_text(_truncate(failure.get("message"), 500))
    failure_text = Redactor.redact_text(_truncate(failure.get("failure_text"), 1500))
    kind = _text(failure.get("kind"), default="failure")
    severity = _severity(kind, check_name, message)
    redacted_url = Redactor.redact_url(url)
    redacted_classname = Redactor.redact_text(_truncate(failure.get("classname"), 300))
    redacted_name = Redactor.redact_url(Redactor.redact_text(_truncate(failure.get("name"), 300)))
    remediation = "Review the OpenAPI contract, API implementation, and auth expectations for this operation."
    source_fingerprint = _source_fingerprint(
        account_id=account_id,
        method=method,
        url=redacted_url,
        check_name=check_name,
        classname=redacted_classname,
        name=redacted_name,
    )
    # Extract real HTTP method/url/status from the failure text when schemathesis
    # includes an HTTP block (Request: … / HTTP/1.1 NNN …).
    raw_failure_text = (failure.get("failure_text") or failure.get("message") or "")
    extracted_req, extracted_resp = _extract_schemathesis_request_response(
        raw_failure_text, base_url=target_url
    )
    received_resp = {"body": failure_text or message}
    if extracted_resp.get("status_code"):
        received_resp["status_code"] = extracted_resp["status_code"]
    sent_req = extracted_req if extracted_req.get("method") else None

    evidence = finalize_finding_evidence({
        "engine": "schemathesis",
        "confirmation": {
            "confirmed": None,
            "status": "UNCONFIRMED",
            "reason": "external_engine_single_observation",
        },
        "source_fingerprint": source_fingerprint,
        "scope_validation": scope_validation,
        "target": Redactor.redact_url(target_url),
        "testcase": {
            "classname": redacted_classname,
            "name": redacted_name,
        },
        "failure": {
            "kind": kind,
            "check": check_name,
            "type": _truncate(failure.get("failure_type"), 200),
            "message": message,
            "failure_text": failure_text,
        },
    },
        method=method,
        url=url,
        matched_rule={
            "check": check_name,
            "kind": kind,
            "type": _truncate(failure.get("failure_type"), 200),
        },
        received_response=received_resp,
        sent_request=sent_req,
        similarity={
            "source": "schemathesis_check",
            "check": check_name,
        },
        remediation=remediation,
    )

    return {
        "account_id": account_id,
        "template_id": _truncate(f"schemathesis-{check_name}", 100),
        "endpoint_id": None,
        "url": redacted_url,
        "method": method,
        "severity": severity,
        "type": _truncate(f"SCHEMATHESIS:{check_name}", 100),
        "description": f"Schemathesis {kind}: {message}",
        "status": "OPEN",
        "confidence": vulnerability_confidence_from_evidence(evidence),
        "remediation": evidence["remediation"],
        "evidence": evidence,
    }


async def persist_schemathesis_junit(
    db: AsyncSession,
    *,
    account_id: int,
    target_url: str,
    junit_xml: str,
) -> dict[str, Any]:
    root = _safe_parse_junit(junit_xml)
    validate_pentest_target(target_url)
    testcase_count = _count_testcases(root)
    failures = list(_iter_failures_from_root(root, target_url=target_url))
    created_count = 0
    merged_count = 0
    vulnerabilities: list[dict[str, Any]] = []

    for failure in failures:
        failure["url"] = validate_pentest_evidence_url(failure.get("url"), target_url=target_url)
        vulnerability_data = build_schemathesis_vulnerability_data(
            failure,
            account_id=account_id,
            target_url=target_url,
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
                "method": vulnerability.method,
                "occurrence_count": int(vulnerability.occurrence_count or 1),
            }
        )

    return {
        "testcases_imported": testcase_count,
        "failures_imported": len(failures),
        "created_count": created_count,
        "merged_count": merged_count,
        "vulnerabilities": vulnerabilities,
    }
