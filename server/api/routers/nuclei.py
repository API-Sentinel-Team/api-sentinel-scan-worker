"""Nuclei vulnerability scanner integration."""
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, select, update, delete

from server.modules.persistence.database import get_db
from server.config import settings
from server.models.core import NucleiScan, NucleiTemplate
from server.modules.auth.rbac import Permission, RBAC, can_run_nuclei
from server.modules.nuclei.findings import persist_nuclei_findings, redact_nuclei_finding
from server.modules.nuclei.runner import NucleiRunner
from server.modules.nuclei.selectors import (
    normalize_severities,
    normalize_tags,
    normalize_template_ids,
    safe_template_filename,
)
from server.modules.pentest.auth_preflight import active_scan_auth_required
from server.modules.pentest.target_policy import target_guard_policy_for_error, validate_pentest_target
from server.modules.test_executor.kill_switch import (
    KILL_SWITCH_REASON,
    PentestKillSwitchError,
    guard_pentest_execution,
)
from server.modules.test_executor.target_guard import TargetGuardError
from server.modules.utils.finding_fingerprint import collapse_by_fingerprint, nuclei_fingerprint
from server.modules.utils.redactor import Redactor

router = APIRouter(tags=["Nuclei Scanner"])


def _target_guard_exception(exc: TargetGuardError, *, target_url: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "target_guard_blocked",
            "target_guard_policy": target_guard_policy_for_error(exc, fallback_url=target_url),
        },
    )


def _auth_profile_required_exception() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": (
                "Legacy Nuclei scans require an authenticated pentest profile. "
                "Use /api/pentest/profiles/{profile_id}/nuclei/run for authenticated execution."
            ),
            "reason": "auth_profile_required",
        },
    )


def _selector_exception(exc: ValueError) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "invalid_nuclei_selector",
        },
    )


def _runtime_unavailable_exception() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={
            "message": "Nuclei runtime is unavailable; no scan was executed.",
            "reason": "nuclei_runtime_unavailable",
            "install_docs": "https://github.com/projectdiscovery/nuclei",
        },
    )


def _safe_custom_template_path(custom_template_dir: str, filename: str) -> str:
    root = os.path.abspath(custom_template_dir)
    path = os.path.abspath(os.path.join(root, filename))
    if os.path.commonpath([root, path]) != root:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "custom template filename escaped the temporary scan directory",
                "reason": "invalid_custom_template_path",
            },
        )
    return path


def _custom_template_directory() -> str:
    """Create a writable, isolated directory for one scan's custom templates.

    The configured scan work directory is preferred over the process-global
    temporary directory.  On Windows, managed endpoint policies can create
    process temp directories with ACLs that deny the worker from opening files
    it just created; the scan work directory is application-owned and is also
    the directory used by the other isolated pentest runners.
    """
    configured_root = str(getattr(settings, "PENTEST_SCAN_WORK_DIR", "") or "").strip()
    if configured_root:
        root = os.path.join(configured_root, "nuclei-custom")
        try:
            os.makedirs(root, mode=0o700, exist_ok=True)
            return tempfile.mkdtemp(prefix="nuclei_custom_", dir=root)
        except OSError:
            # Preserve the existing runtime fallback when a deployment mounts
            # the configured work directory read-only.
            pass
    return tempfile.mkdtemp(prefix="nuclei_custom_")


def _normalize_custom_template_ids(values: List[str]) -> List[str]:
    if len(values or []) > 100:
        raise ValueError("custom_template_ids may contain at most 100 entries")
    normalized: List[str] = []
    seen: set[str] = set()
    for raw in values or []:
        try:
            template_id = str(uuid.UUID(str(raw or "").strip()))
        except ValueError as exc:
            raise ValueError("custom_template_ids contains an invalid UUID") from exc
        if template_id in seen:
            continue
        seen.add(template_id)
        normalized.append(template_id)
    return normalized


@router.get("/status")
async def nuclei_status(
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
):
    available = NucleiRunner.is_available()
    return {
        "nuclei_available": available,
        "mode": "live" if available else "unavailable",
        "simulation_enabled": False,
        "install_docs": "https://github.com/projectdiscovery/nuclei" if not available else None,
    }


@router.post("/scan")
async def start_scan(
    target: str = Body(..., description="Base URL to scan, e.g. https://api.example.com"),
    template_ids: List[str] = Body(default=[]),
    custom_template_ids: List[str] = Body(default=[], description="IDs from /nuclei/templates"),
    tags: List[str] = Body(default=[]),
    severity: List[str] = Body(default=[]),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db)
):
    account_id = payload["account_id"]
    try:
        guard_pentest_execution()
    except PentestKillSwitchError as exc:
        raise HTTPException(status_code=503, detail=KILL_SWITCH_REASON) from exc
    if active_scan_auth_required():
        raise _auth_profile_required_exception()

    try:
        validate_pentest_target(target)
        template_ids = normalize_template_ids(template_ids)
        custom_template_ids = _normalize_custom_template_ids(custom_template_ids)
        tags = normalize_tags(tags)
        severity = normalize_severities(severity)
    except TargetGuardError as exc:
        raise _target_guard_exception(exc, target_url=target) from exc
    except ValueError as exc:
        raise _selector_exception(exc) from exc

    scan = NucleiScan(id=str(uuid.uuid4()), account_id=account_id, target=target,
                      template_ids=template_ids, custom_template_ids=custom_template_ids,
                      tags=tags, severity_filter=severity,
                      status="RUNNING", started_at=datetime.now(timezone.utc))
    db.add(scan)
    await db.commit()

    # Write custom templates to a temp directory and pass as extra paths
    custom_template_dir = None
    extra_template_paths = []
    if custom_template_ids:
        cust_result = await db.execute(
            select(NucleiTemplate).where(
                NucleiTemplate.id.in_(custom_template_ids),
                NucleiTemplate.account_id == account_id,
                NucleiTemplate.enabled == True,
            )
        )
        custom_templates = cust_result.scalars().all()
        if custom_templates:
            custom_template_dir = _custom_template_directory()
            for ct in custom_templates:
                fname = safe_template_filename(ct.template_id, ct.id)
                fpath = _safe_custom_template_path(custom_template_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(ct.yaml_content)
                extra_template_paths.append(fpath)

    try:
        result = await NucleiRunner.run_scan(
            target,
            template_ids=template_ids or None,
            tags=tags or None,
            severity=severity or None,
            extra_template_paths=extra_template_paths or None,
        )
    finally:
        if custom_template_dir:
            shutil.rmtree(custom_template_dir, ignore_errors=True)

    if result["status"] == "RUNTIME_UNAVAILABLE":
        scan.status = result["status"]
        scan.findings = []
        scan.total_found = 0
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        raise _runtime_unavailable_exception()

    safe_findings = [
        redact_nuclei_finding(finding, target=target, account_id=account_id, include_fingerprint=True)
        for finding in result["findings"]
    ]
    unique_findings, duplicate_findings = collapse_by_fingerprint(
        safe_findings,
        lambda finding: nuclei_fingerprint(finding, target=target, account_id=account_id),
    )
    historical_result = await db.execute(
        select(NucleiScan)
        .where(
            NucleiScan.account_id == account_id,
            NucleiScan.target == target,
            NucleiScan.id != scan.id,
        )
        .order_by(NucleiScan.created_at.desc())
        .limit(20)
    )
    historical_fingerprints = {
        nuclei_fingerprint(finding, target=hist.target, account_id=account_id)
        for hist in historical_result.scalars().all()
        for finding in (hist.findings or [])
    }
    repeated_findings = [
        finding for finding in unique_findings
        if nuclei_fingerprint(finding, target=target, account_id=account_id) in historical_fingerprints
    ]
    new_findings = [
        finding for finding in unique_findings
        if nuclei_fingerprint(finding, target=target, account_id=account_id) not in historical_fingerprints
    ]

    scan.status = result["status"]
    scan.findings = unique_findings
    scan.total_found = len(unique_findings)
    scan.completed_at = datetime.now(timezone.utc)
    try:
        vulnerability_summary = await persist_nuclei_findings(
            db,
            account_id=account_id,
            target=target,
            findings=unique_findings,
        )
    except TargetGuardError as exc:
        scan.status = "REJECTED"
        scan.findings = []
        scan.total_found = 0
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        raise _target_guard_exception(exc, target_url=target) from exc
    await db.commit()

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "total_found": scan.total_found,
        "new_findings": len(new_findings),
        "repeated_findings": len(repeated_findings),
        "deduplicated_findings": len(duplicate_findings),
        "vulnerabilities_created": vulnerability_summary["created_count"],
        "vulnerabilities_merged": vulnerability_summary["merged_count"],
        "vulnerabilities": vulnerability_summary["vulnerabilities"][:10],
        "findings": [
            redact_nuclei_finding(finding, target=target, account_id=account_id, include_fingerprint=True)
            for finding in scan.findings[:10]
        ],
        "note": result.get("note"),
    }


@router.get("/scans")
async def list_scans(
    limit: int = Query(50),
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiScan).where(NucleiScan.account_id == account_id)
        .order_by(NucleiScan.created_at.desc()).limit(limit)
    )
    scans = result.scalars().all()
    return {
        "total": len(scans),
        "scans": [
            {
                "id": s.id,
                "target": Redactor.redact_url(str(s.target or "")),
                "status": s.status,
                "total_found": s.total_found,
                "tags": s.tags,
                "severity_filter": s.severity_filter,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
            }
            for s in scans
        ],
    }


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiScan).where(and_(NucleiScan.id == scan_id, NucleiScan.account_id == account_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": scan.id,
        "target": Redactor.redact_url(str(scan.target or "")),
        "status": scan.status,
        "total_found": scan.total_found,
        "findings": [
            redact_nuclei_finding(finding, target=scan.target, account_id=account_id, include_fingerprint=True)
            for finding in (scan.findings or [])
        ],
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }


# ── Custom template management ────────────────────────────────────────────────

@router.get("/templates")
async def list_custom_templates(
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List all custom Nuclei templates uploaded for this account."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiTemplate).where(NucleiTemplate.account_id == account_id)
        .order_by(NucleiTemplate.created_at.desc())
    )
    templates = result.scalars().all()
    return {"total": len(templates), "templates": [_serialize_template(template) for template in templates]}


@router.post("/templates")
async def create_custom_template(
    name: str = Body(...),
    yaml_content: str = Body(..., description="Full Nuclei YAML template content"),
    description: Optional[str] = Body(None),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Upload a custom Nuclei YAML template. Parses id/severity/tags from the content."""
    import yaml as _yaml
    account_id = payload["account_id"]
    template_id = None
    severity = "medium"
    tags = []
    try:
        parsed = _yaml.safe_load(yaml_content)
        if parsed:
            template_id = parsed.get("id")
            info = parsed.get("info", {})
            severity = info.get("severity", "medium")
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
    except Exception:
        pass
    try:
        template_id = normalize_template_ids([template_id])[0] if template_id else None
        severity = (normalize_severities([severity]) or ["medium"])[0]
        tags = normalize_tags(tags)
    except ValueError as exc:
        raise _selector_exception(exc) from exc

    t = NucleiTemplate(
        id=str(uuid.uuid4()), account_id=account_id, name=name,
        template_id=template_id, description=description,
        severity=severity, tags=tags, yaml_content=yaml_content,
    )
    db.add(t)
    await db.commit()
    return {"id": t.id, "name": name, "template_id": template_id,
            "severity": severity, "status": "created"}


@router.patch("/templates/{template_id}")
async def toggle_custom_template(
    template_id: str,
    enabled: bool = Body(..., embed=True),
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable a custom Nuclei template."""
    account_id = payload["account_id"]
    await db.execute(
        update(NucleiTemplate)
        .where(and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id))
        .values(enabled=enabled)
    )
    await db.commit()
    return {"template_id": template_id, "enabled": enabled}


@router.delete("/templates/{template_id}")
async def delete_custom_template(
    template_id: str,
    payload: dict = Depends(can_run_nuclei),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom Nuclei template."""
    account_id = payload["account_id"]
    await db.execute(
        delete(NucleiTemplate).where(
            and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id)
        )
    )
    await db.commit()
    return {"deleted": template_id}


@router.get("/templates/{template_id}/content")
async def get_template_content(
    template_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.NUCLEI_RUN)),
    db: AsyncSession = Depends(get_db),
):
    """Return the raw YAML content of a custom template."""
    account_id = payload["account_id"]
    result = await db.execute(
        select(NucleiTemplate).where(
            and_(NucleiTemplate.id == template_id, NucleiTemplate.account_id == account_id)
        )
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Template not found")
    return {
        "id": t.id,
        "name": Redactor.redact_text(t.name or ""),
        "yaml_content": Redactor.redact_text(t.yaml_content or ""),
    }


def _serialize_template(template: NucleiTemplate) -> dict:
    return {
        "id": template.id,
        "name": Redactor.redact_text(template.name or ""),
        "template_id": template.template_id,
        "severity": template.severity,
        "tags": Redactor.redact_json(template.tags or []),
        "enabled": template.enabled,
        "description": Redactor.redact_text(template.description or "") if template.description else None,
        "created_at": template.created_at,
    }
