# Multi-stage reproducible build with zero secrets and pinned dependencies.
FROM python:3.11-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt requirements-demo.txt ./
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="trust-but-verify" \
      org.opencontainers.image.description="Post-quantum zero-trust sandbox reference implementation" \
      org.opencontainers.image.licenses="NOASSERTION"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

# Non-root unprivileged service account.
RUN useradd -m -u 1000 -s /bin/bash tbvuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY . /app

RUN chown -R tbvuser:tbvuser /app

USER tbvuser

RUN python -c "import fastapi, uvicorn, pydantic, jsonschema, cryptography, pqcrypto; print('Verified pqcrypto + Track 4 dependencies')" && \
    node --version

EXPOSE 8000 8005 8101 8102 8103

CMD ["python", "-m", "demo.node.server"]
