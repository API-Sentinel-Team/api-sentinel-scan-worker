# syntax=docker/dockerfile:1.7
# Isolated scan worker with Schemathesis, Nuclei, and OWASP ZAP CLIs.
# Recommended platform: linux/amd64 (ZAP ships a Linux amd64 tarball).
#
# Build:
#   DOCKER_BUILDKIT=1 docker build --secret id=gh_token,env=GH_TOKEN -t api-sentinel/scan-worker:local .
# Smoke:
#   docker run --rm api-sentinel/scan-worker:local engines

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/appuser \
    ZAP_HOME=/opt/zaproxy \
    PATH="/opt/zaproxy:/usr/local/bin:${PATH}"

ARG NUCLEI_VERSION=3.11.1
ARG ZAP_VERSION=2.16.1
ARG TARGETARCH=amd64
# Binary checksums (CI-2). Sources: nuclei_<ver>_checksums.txt in the nuclei release,
# and the official checksum table in the ZAP release notes for ZAP_<ver>.
ARG NUCLEI_AMD64_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_ARM64_SHA256=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG ZAP_LINUX_SHA256=5b2eb8319b085121a6e8ad50d69d67dbef8c867166f71a937bfc888d247a2ac1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    gcc \
    libpcap-dev \
    libpq-dev \
    openjdk-21-jre-headless \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Nuclei (ProjectDiscovery)
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64|x86_64) NARCH=amd64 ;; \
      arm64|aarch64) NARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" \
      -o /tmp/nuclei.zip; \
    if [ "${NARCH}" = "amd64" ]; then NUCLEI_SHA="${NUCLEI_AMD64_SHA256}"; else NUCLEI_SHA="${NUCLEI_ARM64_SHA256}"; fi; \
    echo "${NUCLEI_SHA}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip; \
    nuclei -version

# OWASP ZAP (Linux package; primarily amd64)
RUN set -eux; \
    if [ "${TARGETARCH}" != "amd64" ] && [ "${TARGETARCH}" != "x86_64" ]; then \
      echo "WARN: ZAP Linux package is amd64-oriented; arm64 builds may fail" >&2; \
    fi; \
    curl -fsSL \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
      -o /tmp/zap.tar.gz; \
    echo "${ZAP_LINUX_SHA256}  /tmp/zap.tar.gz" | sha256sum -c -; \
    mkdir -p /opt; \
    tar -xzf /tmp/zap.tar.gz -C /opt; \
    mv "/opt/ZAP_${ZAP_VERSION}" /opt/zaproxy; \
    ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh; \
    chmod +x /opt/zaproxy/zap.sh; \
    rm -f /tmp/zap.tar.gz; \
    zap.sh -cmd -version

COPY requirements-scan-worker.txt pyproject.toml ./
# Schemathesis 4.x needs pytest>=9, so it lives in its own requirements file and the image never
# installs the test extra. sentinel-core is private: the token comes from a BuildKit secret.
RUN pip install --no-cache-dir --upgrade pip \
    && apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
# sentinel-core is a private repo: the token comes from a BuildKit secret and never lands in a layer.
RUN --mount=type=secret,id=gh_token \
    git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/" \
    && pip install "sentinel-core @ git+https://github.com/API-Sentinel-Team/api-sentinel-core.git@v0.3.4" \
    ; rc=$?; git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadof || true; exit $rc
RUN pip install --no-cache-dir -r requirements-scan-worker.txt && schemathesis --version

COPY sentinel_worker/ ./sentinel_worker/
RUN pip install --no-deps --no-cache-dir .
COPY infra/scripts/scan-worker-entrypoint.sh /usr/local/bin/scan-worker-entrypoint.sh

RUN useradd -m -u 1000 appuser \
    && mkdir -p /app/data/archives /tmp/api-sentinel-scan /home/appuser/.ZAP \
    && sed -i 's/\r$//' /usr/local/bin/scan-worker-entrypoint.sh \
    && chmod +x /usr/local/bin/scan-worker-entrypoint.sh \
    && chown -R appuser:appuser /app /tmp/api-sentinel-scan /opt/zaproxy /home/appuser

USER appuser

ENTRYPOINT ["/usr/local/bin/scan-worker-entrypoint.sh"]
CMD ["worker"]
