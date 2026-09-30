"""Nuclei engine behavior that used to be exercised through the API's legacy scan route.

Execution now lives in the scan-worker, so these tests target the worker-side runner and the
shared finding-persistence code directly, keeping the same safety guarantees: target-guard and
selector validation happen before anything runs, a missing binary fails closed, out-of-scope
findings never become vulnerabilities, and secrets never reach stored evidence.
"""
import os

import pytest
from sqlalchemy import select

from sentinel_core.models import core as models
from sentinel_core.modules.nuclei.findings import persist_nuclei_findings
from sentinel_core.modules.nuclei.selectors import safe_template_filename
from sentinel_core.modules.test_executor.target_guard import TargetGuardError
from sentinel_worker.modules.nuclei.runner import NucleiRunner

ACCOUNT_ID = 1000000


def _finding(template_id: str, severity: str = "high", matched_at: str = "https://api.example.com/admin") -> dict:
    return {
        "template-id": template_id,
        "name": "Exposed Admin Console",
        "severity": severity,
        "matched-at": matched_at,
        "info": {"description": "Admin console reachable"},
    }


@pytest.mark.asyncio
async def test_persist_nuclei_findings_promotes_findings_to_vulnerabilities(db_session):
    summary = await persist_nuclei_findings(
        db_session,
        account_id=ACCOUNT_ID,
        target="https://api.example.com",
        findings=[_finding("exposed-admin", "critical", "https://api.example.com/admin?session=raw-session")],
    )
    await db_session.commit()

    assert summary["created_count"] == 1
    assert summary["merged_count"] == 0
    assert summary["vulnerabilities"][0]["template_id"] == "exposed-admin"
    assert "raw-session" not in str(summary)

    vulnerability = (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.template_id == "exposed-admin"))
    ).scalar_one()
    assert vulnerability.severity == "CRITICAL"
    assert vulnerability.type == "NUCLEI:exposed-admin"
    assert vulnerability.occurrence_count == 1
    assert vulnerability.evidence["engine"] == "nuclei"
    assert "raw-session" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_persist_nuclei_findings_merges_repeated_findings(db_session):
    args = dict(account_id=ACCOUNT_ID, target="https://api.example.com", findings=[_finding("exposed-admin-repeat")])

    first = await persist_nuclei_findings(db_session, **args)
    await db_session.commit()
    second = await persist_nuclei_findings(db_session, **args)
    await db_session.commit()

    assert first["created_count"] == 1
    assert second["created_count"] == 0
    assert second["merged_count"] == 1
    assert second["vulnerabilities"][0]["occurrence_count"] == 2
    rows = (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.template_id == "exposed-admin-repeat"))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2


@pytest.mark.asyncio
async def test_persist_nuclei_findings_rejects_out_of_scope_finding_without_vulnerability(db_session):
    with pytest.raises(TargetGuardError) as exc:
        await persist_nuclei_findings(
            db_session,
            account_id=ACCOUNT_ID,
            target="https://scoped-api.example.com",
            findings=[_finding("metadata-leak", "critical", "http://169.254.169.254/latest/meta-data")],
        )

    assert "metadata" in str(exc.value)
    assert (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.template_id == "metadata-leak"))
    ).scalars().all() == []


@pytest.mark.asyncio
async def test_runner_blocks_target_guard_before_executing():
    with pytest.raises(TargetGuardError) as exc:
        await NucleiRunner.run_scan("http://169.254.169.254/latest/meta-data")

    assert "metadata" in str(exc.value)
    assert exc.value.target_guard_policy["policy"] == "target_guard"
    assert exc.value.target_guard_policy["blocked"] is True
    assert exc.value.target_guard_policy["url"] == "http://169.254.169.254/latest/meta-data"


@pytest.mark.asyncio
async def test_runner_rejects_invalid_selector_before_executing(monkeypatch):
    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: True))

    with pytest.raises(ValueError):
        await NucleiRunner.run_scan("https://invalid-selector.example.com", template_ids=["../../escape"])


@pytest.mark.asyncio
async def test_runner_fails_closed_when_binary_missing(monkeypatch):
    monkeypatch.setattr(NucleiRunner, "is_available", staticmethod(lambda: False))

    result = await NucleiRunner.run_scan("https://api.example.com")

    assert result["status"] == "RUNTIME_UNAVAILABLE"
    assert result["reason"] == "nuclei_runtime_unavailable"
    assert result["findings"] == []
    assert result["total_found"] == 0
    assert "no scan was executed" in result["note"]


@pytest.mark.parametrize("hostile", ["../escape", r"..\escape", "a/../../b", "/etc/passwd", "..", ""])
def test_custom_template_filenames_cannot_escape_the_scan_directory(hostile):
    name = safe_template_filename(hostile, "fallback-id")

    assert name.endswith(".yaml")
    assert "/" not in name
    assert "\\" not in name
    assert os.path.basename(name) == name
    assert not name.startswith(".")


def test_hostile_stored_template_id_is_flattened_to_a_plain_filename():
    assert safe_template_filename("../escape", "fallback-id") == "escape.yaml"
