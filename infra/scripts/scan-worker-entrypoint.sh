#!/usr/bin/env bash
# Entrypoint for Dockerfile.scan-worker.
# Commands:
#   worker   — poll and execute queued scan runs (default)
#   engines  — print CLI readiness for Schemathesis/Nuclei/ZAP and exit
#   --help   — show python worker CLI help
set -euo pipefail

cmd="${1:-worker}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "${cmd}" in
  worker)
    exec python -m server.modules.test_executor.scan_worker "$@"
    ;;
  engines|check-engines)
    status=0
    echo "=== scan-worker engine readiness ==="
    if command -v schemathesis >/dev/null 2>&1; then
      echo "schemathesis: READY ($(schemathesis --version 2>&1 | head -n 1))"
    else
      echo "schemathesis: MISSING"
      status=1
    fi
    if command -v nuclei >/dev/null 2>&1; then
      echo "nuclei: READY ($(nuclei -version 2>&1 | head -n 1))"
    else
      echo "nuclei: MISSING"
      status=1
    fi
    if command -v zap.sh >/dev/null 2>&1; then
      echo "zap: READY ($(zap.sh -cmd -version 2>&1 | head -n 1))"
    else
      echo "zap: MISSING"
      status=1
    fi
    exit "${status}"
    ;;
  -h|--help|help)
    exec python -m server.modules.test_executor.scan_worker --help
    ;;
  *)
    # Allow `docker run ... python ...` style overrides via entrypoint replacement.
    exec "${cmd}" "$@"
    ;;
esac
