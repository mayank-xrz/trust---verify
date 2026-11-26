# Multi-stage reproducible build with zero secrets and pinned dependencies
FROM python:3.11-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build and install NIST PQC shared library (liboqs 0.16.0) with bounded parallelism
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build /tmp/liboqs/build -j 2 && \
    cmake --install /tmp/liboqs/build && \
    rm -rf /tmp/liboqs

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Runtime Stage
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_PATH="/usr/local" \
    LD_LIBRARY_PATH="/usr/local/lib" \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
RUN ldconfig

# Non-root unprivileged service account
RUN useradd -m -u 1000 -s /bin/bash tbvuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY . /app

RUN chown -R tbvuser:tbvuser /app

USER tbvuser

RUN python -c "import fastapi, uvicorn, pydantic, jsonschema, cryptography, oqs; print('Verified liboqs:', oqs.oqs_version())"

EXPOSE 8000 8001 8002 8003 8005

CMD ["python", "-m", "src.node.server"]
