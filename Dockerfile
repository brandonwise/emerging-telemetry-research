FROM python:3.12.11-slim-bookworm

ARG UV_VERSION=0.10.10

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}" \
    RADAR_API_REPORT_ROOT="/var/lib/threat-radar/reports"

RUN python -m pip install --no-cache-dir --disable-pip-version-check "uv==${UV_VERSION}" \
    && groupadd --system --gid 65532 radar \
    && useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent radar \
    && mkdir -p /app /var/lib/threat-radar/reports \
    && chown -R radar:radar /app /var/lib/threat-radar

WORKDIR /app

COPY --chown=radar:radar pyproject.toml uv.lock README.md SECURITY.md LICENSE ./
COPY --chown=radar:radar apps ./apps
COPY --chown=radar:radar packages ./packages
COPY --chown=radar:radar schemas ./schemas
COPY --chown=radar:radar config ./config
COPY --chown=radar:radar integrations ./integrations
COPY --chown=radar:radar migrations ./migrations
COPY --chown=radar:radar missions ./missions
COPY --chown=radar:radar openapi ./openapi
COPY --chown=radar:radar openclaw ./openclaw
COPY --chown=radar:radar policies ./policies
COPY --chown=radar:radar docs ./docs

RUN uv sync --frozen --no-dev

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
