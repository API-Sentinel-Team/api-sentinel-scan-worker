"""Live-target benchmark runner.

Drives the platform's real engines against a running vulnerable target and feeds
the resulting findings into the scoring layer. This is the part that actually
proves detection quality end-to-end.

It deliberately depends on a *reachable* target. When the target is down it
returns ``None`` so callers (CLI, tests) can skip rather than fail — the harness
must never make the normal unit suite red just because Docker isn't running.

Usage (manual, with VAmPI up on :5000):

    python -m tests.benchmark.runner tests/benchmark/corpus/vampi.yaml

The engine wiring is intentionally minimal and explicit. As the platform grows
authenticated multi-identity execution, extend ``_run_engines`` to pass real
auth profiles and identity matrices — the scoring contract does not change.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any
from urllib.parse import urlparse

import httpx

from tests.benchmark.corpus import Corpus
from tests.benchmark.report import scorecard, summary_line, to_json
from tests.benchmark.scoring import BenchmarkResult, score


def target_reachable(base_url: str, *, timeout: float = 2.0) -> bool:
    """Cheap liveness probe so we can skip cleanly when the target is down."""
    try:
        resp = httpx.get(base_url, timeout=timeout)
        return resp.status_code < 600
    except (httpx.HTTPError, OSError):
        return False


def _finding_from_engine_result(
    *, method: str, path: str, engine_result: dict[str, Any]
) -> dict[str, Any]:
    """Adapt an ExecutionEngine result dict into the scoring engine's input shape."""
    info = engine_result.get("info") if isinstance(engine_result.get("info"), dict) else {}
    return {
        "method": method,
        "path": path,
        "type": engine_result.get("type") or engine_result.get("template_id"),
        "owasp_category": engine_result.get("owasp_category"),
        "severity": (engine_result.get("severity") or info.get("severity") or "INFO"),
        "is_vulnerable": bool(engine_result.get("is_vulnerable")),
    }


async def _run_engines(
    corpus: Corpus,
    *,
    max_templates: int | None = None,
    per_test_timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Run the platform's engines against each corpus endpoint, collect findings.

    NOTE: this drives the deterministic template ExecutionEngine. BOLA/BFLA
    multi-identity replay and the multi-engine orchestrator can be layered in
    here as they become wired for live targets; the scoring contract is stable.

    ``max_templates`` caps how many templates are tried per endpoint (the full
    library is ~200+ templates; capping keeps a smoke run fast). ``per_test_timeout``
    bounds each individual test so a hung/crashing target endpoint cannot stall
    the whole benchmark.
    """
    from sentinel_worker.modules.test_executor.execution_engine import ExecutionEngine
    from sentinel_core.modules.test_executor.wordlist_manager import WordlistManager

    templates = WordlistManager.get_instance().templates
    if max_templates is not None:
        templates = templates[:max_templates]
    engine = ExecutionEngine(
        test_id="benchmark", allow_state_change=False, timeout_seconds=per_test_timeout
    )

    findings: list[dict[str, Any]] = []
    total = len(corpus.ground_truth) * len(templates)
    done = 0
    for gt in corpus.ground_truth:
        endpoint = _endpoint_for(corpus.base_url, gt.method, gt.path)
        for template in templates:
            try:
                result = await asyncio.wait_for(
                    engine.execute_test(endpoint, template), timeout=per_test_timeout + 2.0
                )
            except (Exception, asyncio.TimeoutError) as exc:  # live-target robustness
                result = {"is_vulnerable": False, "error": str(exc), "template_id": template.get("id")}
            done += 1
            if done % 50 == 0:
                print(f"  ...{done}/{total} tests run", file=sys.stderr, flush=True)
            if result.get("is_vulnerable"):
                findings.append(
                    _finding_from_engine_result(
                        method=gt.method, path=gt.path, engine_result=result
                    )
                )
    return findings


def _endpoint_for(base_url: str, method: str, path: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    # Replace templated segments with a concrete probe value so the live target
    # routes the request; the corpus keeps the {template} form for matching.
    concrete_path = "/".join(
        ("1" if seg.startswith("{") and seg.endswith("}") else seg)
        for seg in path.split("/")
    )
    return {
        "method": method.upper(),
        "url": f"{base_url.rstrip('/')}/{concrete_path.lstrip('/')}",
        "path": path,
        "host": parsed.netloc,
        "protocol": parsed.scheme or "http",
    }


async def _run_agentic(corpus: Corpus, *, test_accounts: list[Any] | None = None) -> list[dict[str, Any]]:
    """Run the agentic proposer-confirmer path against the corpus endpoints.

    Returns findings in scoring shape. Requires AGENTIC_LLM_ENABLED + a model;
    with no model the strategist makes no proposals and this returns []. When
    ``test_accounts`` (>=2 identities) are supplied, BOLA/BFLA proposals are
    confirmed via authenticated multi-identity replay.
    """
    from sentinel_core.config import settings
    from sentinel_worker.modules.agentic.orchestration import run_agentic_scan_async
    from sentinel_worker.modules.test_executor.execution_engine import ExecutionEngine
    from sentinel_core.modules.test_executor.wordlist_manager import WordlistManager

    templates = WordlistManager.get_instance().templates
    engine = ExecutionEngine(test_id="benchmark-agentic", allow_state_change=False, timeout_seconds=8.0)

    endpoint_dicts = []
    for idx, gt in enumerate(corpus.ground_truth):
        ep = _endpoint_for(corpus.base_url, gt.method, gt.path)
        ep["id"] = f"ep{idx}"
        ep["auth_types_found"] = ["bearer"]
        endpoint_dicts.append(ep)

    result = await run_agentic_scan_async(
        engine=engine,
        endpoints=endpoint_dicts,
        templates=templates,
        settings=settings,
        test_accounts=test_accounts,
    )
    ep_by_id = {ep["id"]: ep for ep in endpoint_dicts}
    findings = []
    # Collect findings from all three agentic sources: proposer-loop confirmed
    # findings, multi-step attack chains, and the targeted deterministic detectors.
    all_findings = list(result.get("outcome", {}).get("confirmed_findings", []))
    all_findings += result.get("chain_findings", []) or []
    all_findings += result.get("detector_findings", []) or []
    for f in all_findings:
        ep = ep_by_id.get(str(f.get("endpoint_id")), {})
        findings.append(
            {
                "method": ep.get("method", "GET"),
                "path": ep.get("path", "/"),
                "type": f.get("type"),
                "severity": f.get("severity", "MEDIUM"),
                "is_vulnerable": True,
            }
        )
    return findings


def run(
    corpus: Corpus,
    *,
    max_templates: int | None = None,
    agentic: bool = False,
    with_vampi_auth: bool = False,
    with_crapi_auth: bool = False,
) -> BenchmarkResult | None:
    """Run the benchmark against a live target. Returns None if unreachable.

    ``agentic=True`` runs the LLM proposer-confirmer path instead of the raw
    template sweep. ``with_vampi_auth`` / ``with_crapi_auth`` provision two
    identities for that target so the agentic path can confirm BOLA/BFLA via
    multi-identity replay.
    """
    if not target_reachable(corpus.base_url):
        return None
    if agentic:
        test_accounts = None
        if with_vampi_auth:
            from tests.benchmark.targets.vampi_auth import provision_vampi_identities

            test_accounts = provision_vampi_identities(corpus.base_url)
        elif with_crapi_auth:
            from tests.benchmark.targets.crapi_auth import provision_crapi_identities

            test_accounts = provision_crapi_identities(corpus.base_url)
        findings = asyncio.run(_run_agentic(corpus, test_accounts=test_accounts))
    else:
        findings = asyncio.run(_run_engines(corpus, max_templates=max_templates))
    return score(corpus, findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="API Sentinel detection benchmark")
    parser.add_argument("corpus", help="path to a corpus YAML file")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a scorecard")
    parser.add_argument(
        "--slo", type=float, default=0.05, help="max High/Critical FP rate (default 0.05)"
    )
    parser.add_argument(
        "--max-templates",
        type=int,
        default=None,
        help="cap templates per endpoint for a fast smoke run (default: all)",
    )
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="run the agentic proposer-confirmer path (needs AGENTIC_LLM_ENABLED + a model)",
    )
    parser.add_argument(
        "--with-vampi-auth",
        action="store_true",
        help="provision 2 VAmPI identities so agentic BOLA/BFLA replay can confirm",
    )
    parser.add_argument(
        "--with-crapi-auth",
        action="store_true",
        help="provision 2 crAPI identities (signup/login or CRAPI_*_TOKEN env)",
    )
    args = parser.parse_args(argv)

    corpus = Corpus.load(args.corpus)
    result = run(
        corpus,
        max_templates=args.max_templates,
        agentic=args.agentic,
        with_vampi_auth=args.with_vampi_auth,
        with_crapi_auth=args.with_crapi_auth,
    )
    if result is None:
        print(
            f"Target {corpus.base_url} is not reachable; start the vulnerable "
            f"target first (see tests/benchmark/targets/). Skipping.",
            file=sys.stderr,
        )
        return 2

    if args.json:
        print(to_json(result))
    else:
        print(scorecard(result, slo_fp_rate=args.slo))
        print(summary_line(result))
    return 0 if result.meets_slo(args.slo) else 1


if __name__ == "__main__":
    raise SystemExit(main())
