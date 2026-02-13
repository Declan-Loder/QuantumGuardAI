# Stage 1: Builder (heavy deps, compile if needed)
FROM python:3.11-slim-bookworm AS builder

# Set working directory
WORKDIR /app

# Install system dependencies (minimal set for Poetry + ML libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    curl \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libffi-dev \
    liblzma-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry - version pinned for reproducibility
ENV POETRY_VERSION=1.8.3
RUN curl -sSL https://install.python-poetry.org | python3 - --version $POETRY_VERSION
ENV PATH="/root/.local/bin:$PATH"

# Copy only dependency files first (cache layer optimization)
COPY pyproject.toml poetry.lock ./

# Install dependencies into a virtualenv
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Stage 2: Runtime (slim image, no build tools)
FROM python:3.11-slim-bookworm

# Set labels for GitHub Packages / OCI compliance
LABEL org.opencontainers.image.source="https://github.com/Declan-Loder/QuantumGuardAI" \
      org.opencontainers.image.description="Privacy-preserving AI agent framework for enterprise cybersecurity" \
      org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Copy Poetry-installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/

# Create non-root user for security (best practice)
RUN useradd -m -u 1000 quantumguard \
    && chown -R quantumguard:quantumguard /app

USER quantumguard

# Expose ports if/when we add API/server mode (optional for now)
# EXPOSE 8000

# Healthcheck (simple for now - expand later with real endpoint or CLI check)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD poetry run python -c "import sys; sys.exit(0)" || exit 1

# Default entrypoint: run the CLI (can be overridden with docker run)
ENTRYPOINT ["poetry", "run", "python", "-m", "quantumguard.cli"]

# Default command: show help
CMD ["--help"]
