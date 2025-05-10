#!/bin/bash
# ProbeOps API - Docker Startup Script
# This script handles initialization and startup of the ProbeOps API in a Docker container.

# Exit on error
set -e

# Print commands for debugging
if [ "${DEBUG}" = "True" ] || [ "${DEBUG}" = "true" ] || [ "${DEBUG}" = "1" ]; then
    set -x
fi

# Install netcat if not available (needed for database connection check)
if ! command -v nc > /dev/null; then
    echo "Installing netcat for database connection check..."
    apt-get update && apt-get install -y --no-install-recommends netcat-openbsd
fi

# Determine database host from environment
DB_HOST="${POSTGRES_HOST:-db}"
DB_PORT="${POSTGRES_PORT:-5432}"
MAX_RETRIES=30
RETRY_INTERVAL=2

# Wait for the database to be ready
echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT} to be ready..."
RETRIES=0
until nc -z "${DB_HOST}" "${DB_PORT}" || [ ${RETRIES} -eq ${MAX_RETRIES} ]; do
    echo "Waiting for PostgreSQL to be available... (${RETRIES}/${MAX_RETRIES})"
    sleep ${RETRY_INTERVAL}
    RETRIES=$((RETRIES+1))
done

if [ ${RETRIES} -eq ${MAX_RETRIES} ]; then
    echo "Error: PostgreSQL did not become available in time"
    exit 1
fi

echo "PostgreSQL is ready!"

# Load environment variables from .env if it exists and we're not in Docker
if [ -f .env ] && [ -z "${DOCKER_ENV}" ]; then
    echo "Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs -0)
fi

# Print configuration summary
echo "ProbeOps API Configuration:"
echo "- API Port: ${API_PORT:-5000}"
echo "- Database Host: ${DB_HOST}"
echo "- Environment: ${ENVIRONMENT:-production}"
echo "- Workers: ${WORKERS:-4}"
echo "- Timeout: ${WORKER_TIMEOUT:-120}s"
echo "- Keepalive: ${KEEPALIVE:-5}s"

# Run database migrations or initialization
echo "Setting up database tables..."
# Check if flask db command is available (Flask-Migrate)
if python -m flask db --help > /dev/null 2>&1; then
    echo "Running migrations with Flask-Migrate..."
    python -m flask db upgrade
else
    echo "Flask-Migrate not available, falling back to manual schema creation..."
    python -c "from flask_server import app, db; app.app_context().push(); db.create_all()"
fi
echo "Database setup complete."

# Determine number of workers based on environment or CPU cores
if [ -z "${WORKERS}" ]; then
    # Calculate workers based on CPU cores if available
    if command -v nproc > /dev/null; then
        WORKERS=$(($(nproc) * 2 + 1))
        echo "Auto-configuring workers based on CPU cores: ${WORKERS}"
    else
        WORKERS=4
        echo "Using default worker count: ${WORKERS}"
    fi
fi

WORKER_TIMEOUT=${WORKER_TIMEOUT:-120}
KEEPALIVE=${KEEPALIVE:-5}
MAX_REQUESTS=${MAX_REQUESTS:-1000}
MAX_REQUESTS_JITTER=${MAX_REQUESTS_JITTER:-100}

# Start the application
echo "Starting ProbeOps API server with Flask WSGI..."
exec gunicorn --workers "${WORKERS}" \
    --bind "0.0.0.0:${API_PORT:-5000}" \
    --timeout "${WORKER_TIMEOUT}" \
    --keep-alive "${KEEPALIVE}" \
    --max-requests "${MAX_REQUESTS}" \
    --max-requests-jitter "${MAX_REQUESTS_JITTER}" \
    --log-level "${LOG_LEVEL:-info}" \
    --access-logfile - \
    --error-logfile - \
    --forwarded-allow-ips "*" \
    "main:app"