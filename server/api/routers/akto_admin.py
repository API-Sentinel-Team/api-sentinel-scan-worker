
"""Akto-compatible admin API shims — maps Akto-style POST endpoints to our data."""
import time
import random
import datetime
import logging
import hashlib
import secrets
from fastapi import APIRouter, Depends, Body
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from server.modules.persistence.database import get_db
from server.modules.utils.redactor import Redactor
from server.models.core import (
    User, AuditLog, WAFEvent, ThreatConfig,
    ThreatActor, MaliciousEvent, APICollection, APIEndpoint,
    Vulnerability, RequestLog, MaliciousEventRecord, Sensor, Account, AccountSetting, ApiToken,
    PolicyViolation, SampleData,
)
from server.modules.auth.rbac import RBAC, Permission, require_admin

router = APIRouter()
logger = logging.getLogger(__name__)


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _safe_audit_details(log: AuditLog) -> str:
    if log.details is not None:
        return str(Redactor.redact_json(log.details))
    if log.details_encrypted:
        return "[encrypted]"
    return ""


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: list[str] = Field(default_factory=list)
    expiresInDays: int | None = Field(default=90, ge=1, le=3650)


def _deep_merge(base: dict, patch: dict) -> dict:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _license_defaults(plan_tier: str | None) -> dict:
    normalized = (plan_tier or "FREE").upper()
    envelopes = {
        "FREE": {"applicationsPurchased": 2, "endpointAllowance": 500, "sensorAllowance": 1},
        "GROWTH": {"applicationsPurchased": 10, "endpointAllowance": 5000, "sensorAllowance": 5},
        "ENTERPRISE": {"applicationsPurchased": 50, "endpointAllowance": 100000, "sensorAllowance": 50},
    }
    envelope = envelopes.get(normalized, envelopes["FREE"])
    return {
        "planTier": normalized,
        "applicationsPurchased": envelope["applicationsPurchased"],
        "endpointAllowance": envelope["endpointAllowance"],
        "sensorAllowance": envelope["sensorAllowance"],
        "expiresOn": None,
    }


async def _build_account_settings(account_id: int, db: AsyncSession) -> dict:
    account = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    row = (await db.execute(select(AccountSetting).where(AccountSetting.account_id == account_id))).scalar_one_or_none()

    app_count = (await db.execute(
        select(func.count()).select_from(APICollection).where(APICollection.account_id == account_id)
    )).scalar() or 0
    endpoint_count = (await db.execute(
        select(func.count()).select_from(APIEndpoint).where(APIEndpoint.account_id == account_id)
    )).scalar() or 0
    sensor_count = (await db.execute(
        select(func.count()).select_from(Sensor).where(Sensor.account_id == account_id)
    )).scalar() or 0
    policy_count = (await db.execute(
        select(func.count()).select_from(PolicyViolation).where(PolicyViolation.account_id == account_id)
    )).scalar() or 0
    sample_count = (await db.execute(
        select(func.count()).select_from(SampleData).where(SampleData.account_id == account_id)
    )).scalar() or 0

    defaults = {
        "deployment": {
            "mode": "saas",
            "runtimeProfile": "kubernetes",
            "inlineProtection": False,
        },
        "traffic": {
            "source": "nginx",
            "collectorUrl": "",
            "controllerUrl": "",
        },
        "applicationDefaults": {
            "environment": "production",
            "businessUnit": "Core Platform",
            "assignedUsers": [],
        },
        "identity": {
            "authHeader": "authorization",
            "sessionKey": "x-session-id",
            "userIdKey": "x-user-id",
            "userRoleKey": "x-user-role",
            "tenantKey": "x-tenant-id",
        },
        "featureEnvelope": {
            "discovery": True,
            "behavioralTesting": True,
            "realtimeProtection": True,
            "reporting": True,
        },
        "onboarding": {
            "completed": False,
            "currentStep": "deployment",
            "completedSteps": [],
            "validation": {
                "controllerHealthy": sensor_count > 0,
                "trafficSeen": sample_count > 0,
                "inventoryVisible": endpoint_count > 0,
                "policiesEnabled": policy_count > 0,
            },
        },
        "license": _license_defaults(account.plan_tier if account else "FREE"),
    }
    merged = _deep_merge(defaults, row.settings if row and row.settings else {})
    merged["license"] = {
        **merged.get("license", {}),
        "planTier": (account.plan_tier if account else merged.get("license", {}).get("planTier", "FREE")).upper(),
        "applicationsUsed": app_count,
        "endpointUsage": endpoint_count,
        "sensorUsage": sensor_count,
    }
    onboarding_settings = merged.get("onboarding", {})
    merged["onboarding"] = {
        **onboarding_settings,
        "validation": {
            **{
                "controllerHealthy": sensor_count > 0,
                "trafficSeen": sample_count > 0,
                "inventoryVisible": endpoint_count > 0,
                "policiesEnabled": policy_count > 0,
            },
            **(onboarding_settings.get("validation") or {}),
        },
    }
    return merged


def _api_key_summary(token: ApiToken) -> dict:
    created_at = _as_utc(token.created_at)
    expires_at = _as_utc(token.expires_at)
    return {
        "id": token.id,
        "name": token.name,
        "reference": f"key_{token.id[-6:]}",
        "scopes": token.scopes or [],
        "createdAt": created_at.isoformat() if created_at else None,
        "expiresAt": expires_at.isoformat() if expires_at else None,
        "createdBy": token.user_id,
        "status": "EXPIRED" if expires_at and expires_at <= _utc_now() else "ACTIVE",
    }


# ── Module / System Health ────────────────────────────────────────────────────

@router.post("/fetchModuleInfo")
async def fetch_module_info(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Returns runtime module + all registered sensors from DB."""
    account_id = payload.get("account_id")
    modules = [
        {
            "id": "api-sentinel-runtime",
            "moduleName": "API Sentinel Runtime",
            "currentVersion": "1.0.0",
            "lastHeartbeat": int(time.time() * 1000),
            "lastMirrored": int(time.time() * 1000),
            "state": "RUNNING",
            "isConnected": True,
            "hostName": "localhost",
            "ipAddress": "127.0.0.1",
            "policyVersion": "1",
        }
    ]

    result = await db.execute(select(Sensor).where(Sensor.account_id == account_id))
    sensors = result.scalars().all()
    now = time.time()
    for s in sensors:
        hb_ts = s.last_heartbeat.timestamp() if s.last_heartbeat else 0
        # Consider sensor ONLINE if heartbeat within last 60 seconds
        is_online = (now - hb_ts) < 60
        modules.append({
            "id": s.id,
            "moduleName": f"eBPF Sensor — {s.name}",
            "currentVersion": s.version or "v1",
            "lastHeartbeat": int(hb_ts * 1000),
            "lastMirrored": int(hb_ts * 1000),
            "state": "RUNNING" if is_online else "STOPPED",
            "isConnected": is_online,
            "hostName": s.name,
            "ipAddress": s.host or "-",
            "policyVersion": "1",
            "linesShipped": s.lines_shipped or 0,
        })

    return {"moduleInfos": modules}


@router.post("/rebootModules")
async def reboot_modules(payload: dict = Depends(require_admin)):
    return {"success": True}


@router.post("/deleteModuleInfo")
async def delete_module_info(payload: dict = Depends(require_admin)):
    return {"success": True}


# ── Team / Users ──────────────────────────────────────────────────────────────

@router.post("/getTeamData")
async def get_team_data(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(select(User).where(User.account_id == account_id))
    users = result.scalars().all()
    return {
        "users": [
            {
                "id": u.id,
                "login": u.email,
                "name": u.email.split("@")[0],
                "role": u.role,
                "lastLoginTs": int(time.time() * 1000),
                "createdAt": str(u.created_at) if u.created_at else None,
            }
            for u in users
        ],
        "pendingInvitees": [],
    }


@router.post("/getCustomRoles")
async def get_custom_roles(payload: dict = Depends(require_admin)):
    return {
        "customRoles": [
            {"name": r} for r in
            ["ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "MEMBER", "AUDITOR", "VIEWER"]
        ]
    }


@router.post("/createCustomRole")
async def create_custom_role(payload: dict = Depends(require_admin)):
    return {"success": True}


@router.post("/removeUser")
async def remove_user(
    email: str = Body(..., embed=True),
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.email == email, User.account_id == payload["account_id"])
    )
    user = result.scalar_one_or_none()
    if user:
        await db.delete(user)
        await db.commit()
    return {"success": True}


# ── Audit Logs ────────────────────────────────────────────────────────────────

@router.post("/fetchAuditData")
async def fetch_audit_data(
    skip: int = Body(0),
    limit: int = Body(50),
    payload: dict = Depends(RBAC.require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.account_id == account_id)
        .order_by(AuditLog.created_at.desc())
        .offset(skip).limit(limit)
    )
    logs = result.scalars().all()
    total = (await db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.account_id == account_id)
    )).scalar()
    return {
        "auditLogs": [
            {
                "id": str(log.id),
                "user": log.user_id or "",
                "action": log.action or "",
                "timestamp": int(log.created_at.timestamp() * 1000) if log.created_at else 0,
                "details": _safe_audit_details(log),
                "resource": log.resource_type or "",
            }
            for log in logs
        ],
        "total": total,
    }


# ── Account Settings ──────────────────────────────────────────────────────────

@router.post("/getAccountSettingsForAdvancedFilters")
async def get_account_settings(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    settings = await _build_account_settings(payload["account_id"], db)
    return {"accountSettings": settings}


@router.post("/modifyAccountSettings")
async def modify_account_settings(
    settings_patch: dict = Body(default_factory=dict),
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    row = (
        await db.execute(select(AccountSetting).where(AccountSetting.account_id == account_id))
    ).scalar_one_or_none()
    if row:
        row.settings = _deep_merge(row.settings or {}, settings_patch)
    else:
        row = AccountSetting(account_id=account_id, settings=settings_patch)
        db.add(row)

    await db.commit()
    merged = await _build_account_settings(account_id, db)
    return {"success": True, "accountSettings": merged}


@router.post("/getApiKeys")
async def get_api_keys(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApiToken)
        .where(ApiToken.account_id == payload["account_id"])
        .order_by(ApiToken.created_at.desc())
    )
    tokens = result.scalars().all()
    return {"apiKeys": [_api_key_summary(token) for token in tokens]}


@router.post("/createApiKey")
async def create_api_key(
    req: CreateApiKeyRequest,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    raw_token = f"ask_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    created_by = payload.get("sub") or payload.get("user_id") or "system"
    expires_at = None
    if req.expiresInDays:
        expires_at = _utc_now() + datetime.timedelta(days=req.expiresInDays)

    token = ApiToken(
        user_id=created_by,
        account_id=payload["account_id"],
        name=req.name.strip(),
        token_hash=token_hash,
        scopes=req.scopes,
        expires_at=expires_at,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)

    return {
        "apiKey": _api_key_summary(token),
        "token": raw_token,
    }


@router.post("/revokeApiKey")
async def revoke_api_key(
    apiKeyId: str = Body(..., embed=True),
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    token = (
        await db.execute(
            select(ApiToken).where(
                ApiToken.id == apiKeyId,
                ApiToken.account_id == payload["account_id"],
            )
        )
    ).scalar_one_or_none()
    if not token:
        return {"success": True}

    await db.delete(token)
    await db.commit()
    return {"success": True}


# ── Traffic Alerts ────────────────────────────────────────────────────────────

@router.post("/getAllTrafficAlerts")
async def get_all_traffic_alerts(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WAFEvent)
        .where(WAFEvent.account_id == payload["account_id"])
        .order_by(WAFEvent.created_at.desc())
        .limit(50)
    )
    events = result.scalars().all()
    return {
        "trafficAlerts": [
            {
                "id": str(e.id),
                "message": f"{e.rule_id}: {e.path or ''}",
                "timestamp": int(e.created_at.timestamp() * 1000) if e.created_at else 0,
                "dismissed": False,
            }
            for e in events
        ]
    }


@router.post("/markAlertAsDismissed")
async def mark_alert_dismissed(payload: dict = Depends(RBAC.require_auth)):
    return {"success": True}


# ── Threat Configuration ──────────────────────────────────────────────────────

@router.post("/fetchThreatConfiguration")
async def fetch_threat_configuration(
    payload: dict = Depends(RBAC.require_auth),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload["account_id"]
    result = await db.execute(
        select(ThreatConfig).where(ThreatConfig.account_id == account_id)
    )
    cfg = result.scalar_one_or_none()
    return {
        "threatConfiguration": {
            "archival_enabled": cfg.archival_enabled if cfg else False,
            "archival_days": cfg.archival_days if cfg else 30,
            "actor_config": cfg.actor_config if cfg else {},
            "ratelimit_config": cfg.ratelimit_config if cfg else {},
        }
    }


@router.post("/modifyThreatConfiguration")
async def modify_threat_configuration(payload: dict = Depends(require_admin)):
    return {"success": True}


# ── Demo Seed Data ─────────────────────────────────────────────────────────────

@router.post("/seed-demo")
async def seed_demo_data(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Populate the database with realistic mock data for UI demonstration."""
    account_id = payload["account_id"]
    now = _utc_now()

    _ATTACK_TYPES = [
        "SQL Injection", "XSS", "BOLA", "Broken Auth",
        "SSRF", "Path Traversal", "RCE", "Mass Assignment",
        "Rate Limit Bypass", "JWT Forgery",
    ]
    _METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    _PATHS = [
        "/api/users/{id}", "/api/orders", "/api/admin/settings",
        "/api/products/{id}/delete", "/api/auth/token",
        "/api/payments/process", "/api/files/upload",
        "/api/users/search", "/api/reports/export",
    ]
    _IPS = [
        "185.220.101.47", "194.165.16.29", "45.155.205.225",
        "91.108.4.1", "178.62.54.91", "103.21.244.0",
        "198.51.100.14", "203.0.113.55", "172.16.254.1",
        "10.0.0.99",
    ]
    _SEVERITIES = ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "CRITICAL"]
    _RULES = ["sqli-001", "xss-002", "ratelimit-003", "auth-bypass-004", "ssrf-005"]
    _WAF_ACTIONS = ["BLOCKED", "BLOCKED", "LOGGED", "BLOCKED", "ALLOWED"]

    counts = {"threat_actors": 0, "malicious_events": 0, "waf_events": 0,
              "collections": 0, "endpoints": 0, "vulnerabilities": 0,
              "request_logs": 0, "audit_logs": 0}

    # ── API Collections ────────────────────────────────────────────────────────
    collections = []
    for name, host in [("User Service", "api.internal"), ("Payment Gateway", "pay.internal"),
                       ("Auth Service", "auth.internal"), ("Admin Panel", "admin.internal")]:
        existing = (await db.execute(
            select(APICollection).where(APICollection.account_id == account_id, APICollection.name == name)
        )).scalar_one_or_none()
        if not existing:
            col = APICollection(account_id=account_id, name=name, host=host, type="MIRRORING")
            db.add(col)
            await db.flush()
            collections.append(col)
            counts["collections"] += 1
        else:
            collections.append(existing)

    # ── API Endpoints ──────────────────────────────────────────────────────────
    for col in collections:
        for method in random.sample(_METHODS, 3):
            path = random.choice(_PATHS)
            ep = APIEndpoint(
                account_id=account_id, collection_id=col.id,
                method=method, path=path, host=col.host,
                protocol="https", last_response_code=random.choice([200, 200, 401, 403, 500]),
                risk_score=round(random.uniform(0, 10), 1),
                is_sensitive=random.random() > 0.7,
                api_type="REST", access_type=random.choice(["PUBLIC", "PRIVATE"]),
            )
            db.add(ep)
            counts["endpoints"] += 1

    await db.flush()

    # ── Threat Actors ──────────────────────────────────────────────────────────
    actors = []
    for ip in _IPS:
        existing = (await db.execute(
            select(ThreatActor).where(
                ThreatActor.source_ip == ip,
                ThreatActor.account_id == account_id,
            )
        )).scalar_one_or_none()
        if not existing:
            actor = ThreatActor(
                account_id=account_id,
                source_ip=ip,
                status=random.choice(["MONITORING", "MONITORING", "BLOCKED", "WHITELISTED"]),
                event_count=random.randint(3, 120),
                risk_score=round(random.uniform(0.1, 9.9), 1),
                last_seen=now - datetime.timedelta(minutes=random.randint(1, 1440)),
            )
            db.add(actor)
            await db.flush()
            actors.append(actor)
            counts["threat_actors"] += 1
        else:
            actors.append(existing)

    # ── Malicious Events ───────────────────────────────────────────────────────
    for _ in range(60):
        actor = random.choice(actors)
        ts = now - datetime.timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        event = MaliciousEvent(
            actor_id=actor.id,
            event_type=random.choice(_ATTACK_TYPES),
            severity=random.choice(_SEVERITIES),
            detected_at=ts,
        )
        db.add(event)
        counts["malicious_events"] += 1

    # ── MaliciousEventRecord (richer events for SecurityEvents page) ───────────
    for _ in range(50):
        actor_ip = random.choice(_IPS)
        ts = now - datetime.timedelta(
            days=random.randint(0, 14),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        rec = MaliciousEventRecord(
            account_id=account_id,
            actor=actor_ip,
            ip=actor_ip,
            url=f"https://api.internal{random.choice(_PATHS)}",
            method=random.choice(_METHODS),
            host="api.internal",
            category=random.choice(_ATTACK_TYPES),
            severity=random.choice(_SEVERITIES),
            status=random.choice(["OPEN", "OPEN", "IGNORED", "RESOLVED"]),
            detected_at=int(ts.timestamp() * 1000),
            event_type="EVENT_TYPE_SINGLE",
            payload=f"' OR 1=1 -- ; <script>alert(1)</script>; ../../../etc/passwd"[:60],
        )
        db.add(rec)

    # ── WAF Events ─────────────────────────────────────────────────────────────
    for _ in range(40):
        ts = now - datetime.timedelta(
            days=random.randint(0, 7),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        waf = WAFEvent(
            source_ip=random.choice(_IPS),
            rule_id=random.choice(_RULES),
            action=random.choice(_WAF_ACTIONS),
            method=random.choice(_METHODS),
            path=random.choice(_PATHS),
            severity=random.choice(_SEVERITIES),
            payload_snippet="' OR 1=1 --",
            created_at=ts,
        )
        db.add(waf)
        counts["waf_events"] += 1

    # ── Vulnerabilities ────────────────────────────────────────────────────────
    for _ in range(25):
        ts = now - datetime.timedelta(days=random.randint(0, 30))
        vuln = Vulnerability(
            account_id=account_id,
            template_id=f"tmpl-{random.randint(100,999)}",
            url=f"https://api.internal{random.choice(_PATHS)}",
            method=random.choice(_METHODS),
            severity=random.choice(_SEVERITIES),
            type=random.choice(_ATTACK_TYPES),
            description=f"Detected {random.choice(_ATTACK_TYPES)} vulnerability",
            status=random.choice(["OPEN", "OPEN", "OPEN", "FIXED", "IGNORED"]),
            confidence=random.choice(["HIGH", "MEDIUM", "LOW"]),
            created_at=ts,
        )
        db.add(vuln)
        counts["vulnerabilities"] += 1

    # ── Request Logs ───────────────────────────────────────────────────────────
    for _ in range(80):
        ts = now - datetime.timedelta(
            minutes=random.randint(0, 1440)
        )
        log = RequestLog(
            source_ip=random.choice(_IPS),
            method=random.choice(_METHODS),
            path=random.choice(_PATHS),
            response_code=random.choice([200, 200, 200, 401, 403, 404, 500]),
            response_time_ms=random.randint(10, 2000),
            created_at=ts,
        )
        db.add(log)
        counts["request_logs"] += 1

    # ── Audit Logs ─────────────────────────────────────────────────────────────
    _ACTIONS = ["user.login", "config.update", "test.run", "endpoint.delete",
                "policy.change", "user.invite", "scan.trigger"]
    for _ in range(20):
        ts = now - datetime.timedelta(days=random.randint(0, 30))
        al = AuditLog(
            account_id=account_id,
            action=random.choice(_ACTIONS),
            resource_type="system",
            ip_address=random.choice(_IPS),
            created_at=ts,
        )
        db.add(al)
        counts["audit_logs"] += 1

    await db.commit()
    return {"status": "seeded", "inserted": counts}
