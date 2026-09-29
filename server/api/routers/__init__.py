from fastapi import APIRouter
from . import (
    health, endpoints, tests, vulnerabilities, pii, compliance,
    anomalies, waf, schedules, suites, traffic,
    accounts, auth_mechanisms, dashboard,
    auth, auth_roles, collections, integrations, threat_actors, bola,
    audit_logs, governance, organization, threat_detection,
    # New feature routers
    source_code, cicd, billing, workflows, nuclei, agent_guard, mcp_shield, oauth,
    akto_admin,
    playbooks, retention,
    analytics, storage, enforcement, ml_models, ml_training,
    recon, recon_sources,
    # AppSentinel production routers
    blocklist, alerts, sensors, stream, ingestion, openapi_specs, evidence, business_logic, agentic,
    detection_meta, pentest,
    lineage,
)

try:
    from server.api.websocket import handlers as ws
    _ws_available = True
except ImportError:
    _ws_available = False

router = APIRouter()

# Existing routers
router.include_router(health.router,           prefix="/health")
router.include_router(dashboard.router,        prefix="/dashboard")
router.include_router(endpoints.router,        prefix="/endpoints")
router.include_router(tests.router,            prefix="/tests")
router.include_router(vulnerabilities.router,  prefix="/vulnerabilities")
router.include_router(pii.router,              prefix="/pii")
router.include_router(compliance.router,       prefix="/compliance")
router.include_router(anomalies.router,        prefix="/anomalies")
router.include_router(waf.router,              prefix="/waf")
router.include_router(schedules.router,        prefix="/schedules")
router.include_router(suites.router,           prefix="/suites")
router.include_router(traffic.router,          prefix="/traffic")
router.include_router(accounts.router,         prefix="/accounts")
router.include_router(auth_mechanisms.router,  prefix="/auth-mechanisms")
router.include_router(auth.router,             prefix="/auth")
router.include_router(auth_roles.router,       prefix="/auth-roles")
router.include_router(collections.router,      prefix="/collections")
router.include_router(integrations.router,     prefix="/integrations")
router.include_router(threat_actors.router,    prefix="/threat-actors")
router.include_router(bola.router,             prefix="/bola")
router.include_router(audit_logs.router,       prefix="/audit-logs")
router.include_router(governance.router,       prefix="/governance")
router.include_router(organization.router,     prefix="/organization")
router.include_router(threat_detection.router, prefix="/threat-detection")

# New feature routers
router.include_router(source_code.router,  prefix="/source-code")
router.include_router(cicd.router,         prefix="/cicd")
router.include_router(billing.router,      prefix="/billing")
router.include_router(workflows.router,    prefix="/workflows")
router.include_router(nuclei.router,       prefix="/nuclei")
router.include_router(agent_guard.router,  prefix="/agent-guard")
router.include_router(mcp_shield.router,   prefix="/mcp-shield")
router.include_router(oauth.router,        prefix="/oauth")
router.include_router(akto_admin.router)   # no prefix — paths like /fetchModuleInfo
router.include_router(openapi_specs.router, prefix="/openapi")
router.include_router(evidence.router, prefix="/evidence")
router.include_router(playbooks.router, prefix="/playbooks")
router.include_router(retention.router, prefix="/retention")
router.include_router(analytics.router, prefix="/analytics")
router.include_router(storage.router, prefix="/storage")
router.include_router(enforcement.router, prefix="/enforcement")
router.include_router(ml_models.router, prefix="/ml")
router.include_router(ml_training.router, prefix="/ml")
router.include_router(recon.router, prefix="/recon")
router.include_router(recon_sources.router, prefix="/recon")
router.include_router(pentest.router, prefix="/pentest")

# AppSentinel production routers
router.include_router(blocklist.router, prefix="/blocklist")
router.include_router(alerts.router,    prefix="/alerts")
router.include_router(sensors.router,   prefix="/sensors")
router.include_router(stream.router,    prefix="/stream")
router.include_router(ingestion.router, prefix="/ingestion")
router.include_router(detection_meta.router, prefix="/detection")
router.include_router(business_logic.router, prefix="/business-logic")
router.include_router(agentic.router, prefix="/agentic")
router.include_router(lineage.router, prefix="/lineage")

if _ws_available:
    router.include_router(ws.router, prefix="/ws")
