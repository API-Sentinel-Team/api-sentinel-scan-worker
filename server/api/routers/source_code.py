"""Source code analysis - repos CRUD + scan trigger + findings."""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import APIEndpoint, SourceCodeFinding, SourceCodeRepo
from server.modules.auth.encryption import Encryption
from server.modules.auth.rbac import Permission, RBAC
from server.modules.pentest.target_policy import build_target_guard_policy
from server.modules.persistence.database import get_db
from server.modules.source_code_analyzer.scanner import scan_directory
from server.modules.test_executor.target_guard import TargetGuard, TargetGuardError
from server.modules.utils.finding_fingerprint import source_finding_fingerprint
from server.modules.utils.redactor import Redactor
from server.modules.validation.input_validator import InputValidator, ValidationError

router = APIRouter(tags=["Source Code Analysis"])

ALLOWED_REPO_TYPES = {"LOCAL", "GITHUB", "GITLAB"}
ALLOWED_FINDING_STATUSES = {"OPEN", "FALSE_POSITIVE", "FIXED", "WONT_FIX"}
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _bad_request(exc: Exception) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _validate_uuid(value: str, field_name: str) -> str:
    try:
        return InputValidator.validate_uuid(value, field_name)
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_string(value: str, field_name: str, *, max_length: int, pattern: str | None = None) -> str:
    try:
        return InputValidator.validate_string(
            value,
            field_name,
            max_length=max_length,
            allow_empty=False,
            pattern=pattern,
        )
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _validate_repo_type(repo_type: str) -> str:
    value = _validate_string(repo_type, "repo_type", max_length=50, pattern=r"^[A-Za-z_]+$").upper()
    if value not in ALLOWED_REPO_TYPES:
        raise HTTPException(status_code=400, detail=f"repo_type must be one of {sorted(ALLOWED_REPO_TYPES)}")
    return value


def _validate_branch(branch: str) -> str:
    value = _validate_string(branch or "main", "branch", max_length=100, pattern=r"^[A-Za-z0-9._/-]+$")
    if ".." in value or value.startswith(("/", "-")) or value.endswith("/"):
        raise HTTPException(status_code=400, detail="branch: Invalid branch name")
    return value


def _validate_languages(languages: list) -> list[str]:
    try:
        InputValidator.validate_collection_size(languages, "languages", max_size=50)
        return [
            InputValidator.validate_string(
                str(language),
                f"languages[{index}]",
                max_length=40,
                allow_empty=False,
                pattern=r"^[A-Za-z0-9_+.#-]+$",
            )
            for index, language in enumerate(languages or [])
        ]
    except ValidationError as exc:
        raise _bad_request(exc) from exc


def _repo_guard() -> TargetGuard:
    return TargetGuard(
        allowlist=[],
        allow_private_targets=bool(settings.SOURCE_CODE_ALLOW_PRIVATE_REPOS or settings.DEBUG),
        enforce=bool(settings.SOURCE_CODE_ENFORCE_REPO_GUARD),
        resolve_hosts=bool(settings.SOURCE_CODE_RESOLVE_REPO_HOSTS),
        fail_closed_on_dns_error=bool(settings.SOURCE_CODE_FAIL_CLOSED_ON_REPO_DNS_ERROR),
    )


def _validate_remote_repo_url(repo_url: str | None) -> str:
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required for remote repositories")
    value = _validate_string(repo_url, "repo_url", max_length=2048)
    parsed = urlparse(value)
    if parsed.scheme.lower() != "https":
        raise HTTPException(status_code=400, detail="repo_url: Only https repositories are allowed")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="repo_url: Credentials must be stored in access_token")
    if parsed.query or parsed.fragment:
        raise HTTPException(status_code=400, detail="repo_url: Query strings and fragments are not allowed")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="repo_url: Host is required")
    guard = _repo_guard()
    try:
        guard.validate_url(value, base_url=value)
    except TargetGuardError as exc:
        reason = str(exc).replace("scanner target", "source repository")
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Source repository destination blocked",
                "reason": reason,
                "target_guard_policy": build_target_guard_policy(
                    url=value,
                    base_url=value,
                    reason=reason,
                    guard=guard,
                ),
            },
        ) from exc
    return urlunparse(parsed._replace(netloc=parsed.netloc.lower(), fragment="", query=""))


def _path_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_local_path(local_path: str | None, *, require_exists: bool = True) -> str:
    if not local_path:
        raise HTTPException(status_code=400, detail="local_path is required for LOCAL repositories")
    if len(str(local_path)) > 2048:
        raise HTTPException(status_code=400, detail="local_path: Exceeds max length")
    if not settings.DEBUG and not settings.SOURCE_CODE_ALLOW_LOCAL_PATHS:
        raise HTTPException(status_code=400, detail="Local source-code paths are disabled in this environment")
    try:
        resolved = Path(local_path).expanduser().resolve(strict=require_exists)
    except OSError as exc:
        raise HTTPException(status_code=400, detail="local_path: Cannot be resolved") from exc
    if require_exists and not resolved.is_dir():
        raise HTTPException(status_code=400, detail="local_path: Must be an existing directory")
    if not settings.DEBUG:
        root = Path(settings.SOURCE_CODE_LOCAL_SCAN_ROOT).expanduser().resolve(strict=False)
        if not _path_within(resolved, root):
            raise HTTPException(status_code=400, detail="local_path: Outside configured scan root")
    return str(resolved)


def _safe_repo_url(repo_url: str | None) -> str | None:
    if not repo_url:
        return None
    parsed = urlparse(repo_url)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return Redactor.redact_url(urlunparse(parsed._replace(netloc=netloc)))


def _serialize_repo(repo: SourceCodeRepo) -> dict[str, Any]:
    return {
        "id": repo.id,
        "name": repo.name,
        "repo_type": repo.repo_type,
        "repo_url": _safe_repo_url(repo.repo_url),
        "local_path": "[configured]" if repo.local_path else None,
        "local_path_configured": bool(repo.local_path),
        "branch": repo.branch,
        "languages": repo.languages or [],
        "access_token_configured": bool(repo.access_token),
        "last_scanned_at": repo.last_scanned_at,
        "finding_count": repo.finding_count,
        "created_at": repo.created_at,
    }


def _redact_finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
    safe = dict(finding)
    for field in ("title", "description", "code_snippet", "remediation"):
        if safe.get(field) is not None:
            safe[field] = Redactor.redact_text(str(safe[field]))
    if safe.get("file_path") is not None:
        safe["file_path"] = str(safe["file_path"]).replace("\\", "/")[:2048]
    return safe


def _serialize_finding(finding: SourceCodeFinding) -> dict[str, Any]:
    payload = {
        "id": finding.id,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "code_snippet": finding.code_snippet,
        "remediation": finding.remediation,
        "status": finding.status,
        "endpoint_id": finding.endpoint_id,
        "fingerprint": source_finding_fingerprint(finding),
        "created_at": finding.created_at,
    }
    redacted = _redact_finding_payload(payload)
    redacted["code_snippet_redacted"] = redacted.get("code_snippet") != finding.code_snippet
    return redacted


async def _clone_repo(repo_url: str, branch: str, access_token: Optional[str], dest: str) -> bool:
    """Clone a git repo into dest without exposing the token in process arguments."""
    clone_url = repo_url
    askpass_path = None
    if access_token:
        try:
            token = Encryption.decrypt(access_token)
        except Exception:
            token = access_token
    cmd = ["git", "clone", "--depth", "1", "--branch", branch, clone_url, dest]
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if access_token:
        askpass_path = _write_git_askpass_helper()
        env["GIT_ASKPASS"] = askpass_path
        env["API_SENTINEL_GIT_USERNAME"] = "x-access-token"
        env["API_SENTINEL_GIT_TOKEN"] = token
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        await asyncio.wait_for(proc.communicate(), timeout=120)
        return proc.returncode == 0
    except Exception:
        return False
    finally:
        if askpass_path:
            try:
                os.remove(askpass_path)
            except OSError:
                pass


def _write_git_askpass_helper() -> str:
    suffix = ".cmd" if os.name == "nt" else ".sh"
    fd, path = tempfile.mkstemp(prefix="api_sentinel_git_askpass_", suffix=suffix)
    if os.name == "nt":
        content = (
            "@echo off\r\n"
            "echo %* | findstr /I \"username\" >nul\r\n"
            "if %errorlevel%==0 (\r\n"
            "  echo %API_SENTINEL_GIT_USERNAME%\r\n"
            ") else (\r\n"
            "  echo %API_SENTINEL_GIT_TOKEN%\r\n"
            ")\r\n"
        )
    else:
        content = (
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  *Username*|*username*) printf '%s\\n' \"$API_SENTINEL_GIT_USERNAME\" ;;\n"
            "  *) printf '%s\\n' \"$API_SENTINEL_GIT_TOKEN\" ;;\n"
            "esac\n"
        )
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as helper:
        helper.write(content)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def _extract_endpoint_path(finding: dict) -> Optional[str]:
    if finding.get("finding_type") != "ENDPOINT_DISCOVERED":
        return None
    title = str(finding.get("title") or "")
    if not title.startswith("Endpoint: "):
        return None
    return title.split("Endpoint: ", 1)[1].strip()


@router.get("/repos")
async def list_repos(
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(SourceCodeRepo).where(SourceCodeRepo.account_id == account_id))
    repos = result.scalars().all()
    return {"total": len(repos), "repos": [_serialize_repo(repo) for repo in repos]}


@router.post("/repos")
async def create_repo(
    name: str = Body(...),
    repo_type: str = Body("LOCAL"),
    repo_url: Optional[str] = Body(None),
    local_path: Optional[str] = Body(None),
    branch: str = Body("main"),
    languages: list = Body(default=[]),
    access_token: Optional[str] = Body(None, description="GitHub/GitLab Personal Access Token for private repos"),
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_SCAN)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    validated_type = _validate_repo_type(repo_type)
    validated_repo_url = None
    validated_local_path = None
    if validated_type == "LOCAL":
        validated_local_path = _validate_local_path(local_path, require_exists=True)
    else:
        validated_repo_url = _validate_remote_repo_url(repo_url)

    encrypted_token = Encryption.encrypt(access_token) if access_token else None
    repo = SourceCodeRepo(
        id=str(uuid.uuid4()),
        account_id=account_id,
        name=_validate_string(name, "name", max_length=255),
        repo_type=validated_type,
        repo_url=validated_repo_url,
        local_path=validated_local_path,
        branch=_validate_branch(branch),
        languages=_validate_languages(languages),
        access_token=encrypted_token,
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)
    return {"id": repo.id, "name": repo.name, "status": "created", "repo": _serialize_repo(repo)}


@router.post("/repos/{repo_id}/scan")
async def trigger_scan(
    repo_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_SCAN)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    validated_repo_id = _validate_uuid(repo_id, "repo_id")
    result = await db.execute(
        select(SourceCodeRepo).where(
            and_(SourceCodeRepo.id == validated_repo_id, SourceCodeRepo.account_id == account_id)
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(404, "Repo not found")

    tmp_dir = None
    scan_path = repo.local_path
    try:
        if repo.repo_type in ("GITHUB", "GITLAB"):
            repo_url = _validate_remote_repo_url(repo.repo_url)
            tmp_dir = tempfile.mkdtemp(prefix="soc_scan_")
            cloned = await _clone_repo(repo_url, _validate_branch(repo.branch or "main"), repo.access_token, tmp_dir)
            if not cloned:
                raise HTTPException(502, "Failed to clone source repository. Check repo_url, branch, and token.")
            scan_path = tmp_dir
        elif repo.repo_type == "LOCAL":
            scan_path = _validate_local_path(repo.local_path, require_exists=True)

        if not scan_path:
            raise HTTPException(400, "No local_path or repo_url configured for scanning")

        findings = [_redact_finding_payload(finding) for finding in scan_directory(
            scan_path,
            account_id=account_id,
            repo_id=validated_repo_id,
        )]
        endpoints_result = await db.execute(
            select(APIEndpoint)
            .where(APIEndpoint.account_id == account_id)
            .order_by(APIEndpoint.created_at.desc())
        )
        endpoint_lookup = {}
        for endpoint in endpoints_result.scalars().all():
            if endpoint.path:
                endpoint_lookup.setdefault(endpoint.path, endpoint.id)
            if endpoint.path_pattern:
                endpoint_lookup.setdefault(endpoint.path_pattern, endpoint.id)

        existing_result = await db.execute(
            select(SourceCodeFinding).where(
                SourceCodeFinding.account_id == account_id,
                SourceCodeFinding.repo_id == validated_repo_id,
                SourceCodeFinding.status != "FIXED",
            )
        )
        existing_fingerprints = {
            source_finding_fingerprint(finding) for finding in existing_result.scalars().all()
        }
        batch_fingerprints = set()
        created_fingerprints = []
        deduplicated_count = 0

        for finding in findings:
            endpoint_path = _extract_endpoint_path(finding)
            if endpoint_path and endpoint_lookup.get(endpoint_path):
                finding["endpoint_id"] = endpoint_lookup[endpoint_path]

            fingerprint = source_finding_fingerprint(finding)
            if fingerprint in existing_fingerprints or fingerprint in batch_fingerprints:
                deduplicated_count += 1
                continue

            batch_fingerprints.add(fingerprint)
            created_fingerprints.append(fingerprint)
            db.add(SourceCodeFinding(id=str(uuid.uuid4()), **finding))

        await db.flush()
        active_finding_count = await db.scalar(
            select(func.count(SourceCodeFinding.id)).where(
                SourceCodeFinding.account_id == account_id,
                SourceCodeFinding.repo_id == validated_repo_id,
                SourceCodeFinding.status != "FIXED",
            )
        ) or 0

        await db.execute(
            update(SourceCodeRepo)
            .where(SourceCodeRepo.id == validated_repo_id)
            .values(last_scanned_at=datetime.now(timezone.utc), finding_count=active_finding_count)
        )
        await db.commit()

        return {
            "repo_id": validated_repo_id,
            "findings_found": len(findings),
            "created_findings": len(created_fingerprints),
            "deduplicated_findings": deduplicated_count,
            "created_fingerprints": created_fingerprints[:10],
            "status": "scan_complete",
        }
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.get("/findings")
async def list_findings(
    repo_id: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    query = select(SourceCodeFinding).where(SourceCodeFinding.account_id == account_id)
    if repo_id:
        query = query.where(SourceCodeFinding.repo_id == _validate_uuid(repo_id, "repo_id"))
    if finding_type:
        query = query.where(SourceCodeFinding.finding_type == _validate_string(
            finding_type,
            "finding_type",
            max_length=100,
            pattern=r"^[A-Za-z0-9_:-]+$",
        ))
    if severity:
        validated_severity = _validate_string(severity, "severity", max_length=20).upper()
        if validated_severity not in ALLOWED_SEVERITIES:
            raise HTTPException(status_code=400, detail=f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")
        query = query.where(SourceCodeFinding.severity == validated_severity)
    if status:
        validated_status = _validate_string(status, "status", max_length=20).upper()
        if validated_status not in ALLOWED_FINDING_STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {sorted(ALLOWED_FINDING_STATUSES)}")
        query = query.where(SourceCodeFinding.status == validated_status)
    result = await db.execute(query.limit(limit))
    findings = result.scalars().all()
    return {"total": len(findings), "findings": [_serialize_finding(finding) for finding in findings]}


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    status: str = Body(..., embed=True),
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_SCAN)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    validated_status = _validate_string(status, "status", max_length=20).upper()
    if validated_status not in ALLOWED_FINDING_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(ALLOWED_FINDING_STATUSES)}")
    validated_finding_id = _validate_uuid(finding_id, "finding_id")

    result = await db.execute(
        select(SourceCodeFinding).where(
            and_(SourceCodeFinding.id == validated_finding_id, SourceCodeFinding.account_id == account_id)
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")

    await db.execute(
        update(SourceCodeFinding)
        .where(SourceCodeFinding.id == validated_finding_id)
        .values(status=validated_status)
    )
    await db.commit()
    return {"finding_id": validated_finding_id, "status": validated_status}


@router.get("/summary")
async def findings_summary(
    payload: dict = Depends(RBAC.require_permission(Permission.SOURCE_CODE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(SourceCodeFinding.finding_type, SourceCodeFinding.severity, func.count())
        .where(SourceCodeFinding.account_id == account_id)
        .group_by(SourceCodeFinding.finding_type, SourceCodeFinding.severity)
    )
    return {"summary": [{"finding_type": row[0], "severity": row[1], "count": row[2]} for row in result.all()]}
