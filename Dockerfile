# ===========================================
# ProbeOps API - Production Dockerfile
# ===========================================

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.docker.txt /build/requirements.docker.txt

# Generate wheel packages with all dependencies
RUN pip wheel --wheel-dir=/wheels -r requirements.docker.txt

# Stage 2: Runtime image
FROM python:3.11-slim

# Mark as docker environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DOCKER_ENV=1

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    netcat-openbsd \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file for installation
COPY requirements.docker.txt /app/requirements.docker.txt

# Copy built wheels from builder stage
COPY --from=builder /wheels /wheels

# Install from pre-built wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.docker.txt && rm -rf /wheels

# Copy application code
COPY . /app/

# Make start script executable
RUN chmod +x /app/start.sh

# Create non-root user for security
RUN groupadd -r probeops && \
    useradd -r -g probeops -d /app probeops && \
    chown -R probeops:probeops /app

# Switch to non-root user
USER probeops

# Set default environment variables 
ENV API_PORT=5000 \
    WORKERS=4 \
    ENVIRONMENT=production \
    LOG_LEVEL=INFO

# Expose the port the app runs on
EXPOSE ${API_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${API_PORT}/health || exit 1

# Use the start script as entrypoint
ENTRYPOINT ["/app/start.sh"]