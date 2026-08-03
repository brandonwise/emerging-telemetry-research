FROM python:3.12.13-slim-bookworm

ARG UV_VERSION=0.12.1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}" \
    ETR_API_REPORT_ROOT="/var/lib/telemetry-research/reports"

RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --disable-pip-version-check "uv==${UV_VERSION}" \
    && groupadd --system --gid 65532 research \
    && useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent research \
    && mkdir -p /app /var/lib/telemetry-research/reports \
    && chown -R research:research /app /var/lib/telemetry-research

WORKDIR /app

COPY --chown=research:research pyproject.toml uv.lock README.md SECURITY.md THREAT_MODEL.md THREAT_MODEL_APPROVAL.md LICENSE ./
COPY --chown=research:research apps ./apps
COPY --chown=research:research packages ./packages
COPY --chown=research:research schemas ./schemas
COPY --chown=research:research config ./config
COPY --chown=research:research integrations ./integrations
COPY --chown=research:research migrations ./migrations
COPY --chown=research:research missions ./missions
COPY --chown=research:research openapi ./openapi
COPY --chown=research:research openclaw ./openclaw
COPY --chown=research:research policies ./policies
COPY --chown=research:research docs ./docs
COPY --chown=research:research tests/fixtures/vertical_slice ./tests/fixtures/vertical_slice

RUN uv sync --frozen --no-dev

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
