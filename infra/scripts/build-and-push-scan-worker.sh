#!/usr/bin/env bash
# Build (and optionally push) the isolated scan-worker image with engine CLIs.
#
# Usage:
#   export REGISTRY_IMAGE="registry.example.com/api-sentinel/scan-worker:v1"
#   ./infra/scripts/build-and-push-scan-worker.sh
#
# Optional env:
#   SKIP_PUSH=1           build and tag only
#   SKIP_ENGINE_CHECK=1   skip post-build `engines` smoke check
#   DOCKER_PLATFORM       default linux/amd64
#   NUCLEI_VERSION / ZAP_VERSION  forwarded as build-args

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

if [[ -z "${REGISTRY_IMAGE:-}" ]]; then
  echo "Set REGISTRY_IMAGE to the full tag to build/push, e.g." >&2
  echo "  export REGISTRY_IMAGE=registry.example.com/api-sentinel/scan-worker:v1" >&2
  exit 1
fi

PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
BUILD_ARGS=(
  --platform "${PLATFORM}"
  -f Dockerfile.scan-worker
  -t "${REGISTRY_IMAGE}"
)
if [[ -n "${NUCLEI_VERSION:-}" ]]; then
  BUILD_ARGS+=(--build-arg "NUCLEI_VERSION=${NUCLEI_VERSION}")
fi
if [[ -n "${ZAP_VERSION:-}" ]]; then
  BUILD_ARGS+=(--build-arg "ZAP_VERSION=${ZAP_VERSION}")
fi

echo "==> Building ${REGISTRY_IMAGE} (${PLATFORM})"
docker build "${BUILD_ARGS[@]}" .

if [[ "${SKIP_ENGINE_CHECK:-0}" != "1" ]]; then
  echo "==> Checking engine CLIs inside image"
  docker run --rm --entrypoint /usr/local/bin/scan-worker-entrypoint.sh \
    "${REGISTRY_IMAGE}" engines
fi

if [[ "${SKIP_PUSH:-0}" == "1" ]]; then
  echo "==> SKIP_PUSH=1 — image tagged locally as ${REGISTRY_IMAGE}"
  exit 0
fi

echo "==> Pushing ${REGISTRY_IMAGE}"
docker push "${REGISTRY_IMAGE}"
echo "==> Done"
