# ==============================================================================
# NexThreat Phase 6.5 — Production Multi-Stage Dockerfile
# Architecture: linux/amd64
# Base Image: python:3.14-slim@sha256:810da6270e43d30a1f3e0e1eabbeb6fbd9d78ad9dd2e754d5297a3d6cb42df46
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Ephemeral Dependency Wheel Builder
# ------------------------------------------------------------------------------
FROM --platform=linux/amd64 python:3.14-slim@sha256:810da6270e43d30a1f3e0e1eabbeb6fbd9d78ad9dd2e754d5297a3d6cb42df46 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements.lock /build/requirements.lock

RUN pip wheel --no-cache-dir --require-hashes -r requirements.lock -w /install/wheels

# ------------------------------------------------------------------------------
# Stage 2: Hardened Unprivileged Production Runtime
# ------------------------------------------------------------------------------
FROM --platform=linux/amd64 python:3.14-slim@sha256:810da6270e43d30a1f3e0e1eabbeb6fbd9d78ad9dd2e754d5297a3d6cb42df46 AS runtime

LABEL org.opencontainers.image.title="NexThreat Threat-Detection Platform" \
      org.opencontainers.image.description="Multi-model real-time network telemetry threat-detection API" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="NexThreat" \
      org.opencontainers.image.schema-version="1.0.0" \
      org.opencontainers.image.licenses="Proprietary"

ENV NEXTHREAT_HOST=0.0.0.0 \
    NEXTHREAT_PORT=8000 \
    NEXTHREAT_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=42 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

RUN groupadd -g 10001 -r nexthreat && \
    useradd -u 10001 -r -g nexthreat -d /app -s /usr/sbin/nologin nexthreat

WORKDIR /app

COPY --from=builder /install/wheels /install/wheels
RUN pip install --no-cache-dir --no-index --find-links=/install/wheels /install/wheels/*.whl && \
    rm -rf /install

COPY src/ /app/src/
COPY data/ /app/data/
COPY docs/ /app/docs/

RUN chown -R nexthreat:nexthreat /app && \
    chmod -R 555 /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import http.client, sys; conn = http.client.HTTPConnection('127.0.0.1', 8000, timeout=2); conn.request('GET', '/health'); resp = conn.getresponse(); sys.exit(0 if resp.status == 200 else 1)"

ENTRYPOINT ["python", "-m", "src.api.entrypoint"]
