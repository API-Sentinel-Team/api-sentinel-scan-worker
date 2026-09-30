# api-sentinel-scan-worker

Claims queued scan runs and executes them in an isolated process: the template engine, Schemathesis, Nuclei, ZAP and authorization replay. It is the **only** component that sends attack traffic to targets.

Part of API Sentinel. This repo contains **only this service's code**; everything shared
(database models, migrations, config, tenancy, audit, redaction, pentest policy, scan planning,
the security-test template library) lives in
[`api-sentinel-core`](https://github.com/API-Sentinel-Team/api-sentinel-core), installed as the
`sentinel-core` dependency and pinned to a released tag in `pyproject.toml`.

## Boundaries

- Never import another service's package. Services cooperate only through the database run
  queue and Redis pub/sub. `tests/unit/test_service_boundaries.py` enforces this in the
  api repo; the same rule holds here.
- Schema changes are made in `api-sentinel-core` (the single owner of migrations), never here.

## Run

```bash
docker run --rm api-sentinel/scan-worker:local engines   # readiness check
python -m sentinel_worker.modules.test_executor.scan_worker
```

## Develop

```bash
pip install -e ../api-sentinel-core           # or the pinned tag from pyproject.toml
pip install --no-deps -e ".[test]"
DEBUG=true pytest -q
```

`DEBUG=true` is required by tests: without it `sentinel_core.config` refuses to build settings
(production validation).
