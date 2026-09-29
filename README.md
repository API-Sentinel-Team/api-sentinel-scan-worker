# api-sentinel-scan-worker

Active pentest execution service: claims queued scan runs, executes the
Schemathesis / Nuclei / ZAP engine plans, and persists findings, evidence,
and artifacts.

## Status: vendored build, decoupling pending

This repository currently carries a vendored snapshot of the shared runtime
(`server/`, `migrations/`, `tests-library/`) because the worker still imports
shared models and helpers from it. The image builds and the worker runs, but
this is **not yet an independent microservice**: extracting
`server.modules.test_executor` behind a shared-contracts package is tracked
as the next stage.

## Build and run

```bash
docker build -f Dockerfile.scan-worker -t api-sentinel/scan-worker:local .
docker run --rm api-sentinel/scan-worker:local engines   # engine readiness
docker compose -f ../api-sentinel-api/docker-compose.yml up scan-worker
```

Entry point: `python -m server.modules.test_executor.scan_worker` (see
`infra/scripts/scan-worker-entrypoint.sh`).
