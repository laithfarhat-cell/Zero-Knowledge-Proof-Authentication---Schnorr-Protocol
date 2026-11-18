# syntax=docker/dockerfile:1
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application source.
COPY core ./core
COPY server ./server
COPY client ./client
COPY simulation ./simulation
COPY pyproject.toml README.md THEORY.md ./

# Run as an unprivileged user; keep the SQLite registry on a volume.
RUN groupadd --system app && useradd --system --gid app --home /app app \
    && mkdir -p /data && chown -R app:app /data /app
USER app

ENV SCHNORR_DB_PATH=/data/schnorr_auth.db \
    SCHNORR_HOST=0.0.0.0 \
    SCHNORR_PORT=8000 \
    SCHNORR_GROUP=rfc3526-2048

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)" || exit 1

CMD ["python", "-m", "uvicorn", "server.api:app", "--host", "0.0.0.0", "--port", "8000"]
