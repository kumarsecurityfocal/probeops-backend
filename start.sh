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

# Set Flask application for migrations if not already set
if [ -z "${FLASK_APP}" ]; then
    echo "WARNING: FLASK_APP environment variable was not set. Setting to main:app as fallback."
    export FLASK_APP=main:app
else
    echo "Using FLASK_APP=${FLASK_APP}"
fi

# Run database migrations
echo "Setting up database tables..."
echo "Running migrations with Flask-Migrate..."

# First try to stamp current database state
flask db stamp head || echo "Warning: Could not stamp database revision, may be first run"

# Generate migration if schema changes exist
flask db migrate -m "Auto migration from container startup" || echo "Warning: No schema changes detected"

# Apply migrations
if ! flask db upgrade; then
    echo "Error: Migration failed! Please check database connection and schema compatibility"
    exit 1
fi

# Check for compatibility columns
echo "Verifying compatibility columns..."
PYTHON_CHECK="
import sys
from sqlalchemy import inspect, create_engine
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create minimal app context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = '$DATABASE_URL'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

with app.app_context():
    # Check database schema
    inspector = inspect(db.engine)
    
    if 'users' not in inspector.get_table_names():
        print('Users table does not exist yet')
        sys.exit(0)
    
    columns = {c['name'] for c in inspector.get_columns('users')}
    missing = []
    
    if 'password_hash' not in columns:
        missing.append('password_hash')
    if 'is_admin' not in columns:
        missing.append('is_admin')
    
    if missing:
        print(f'Missing compatibility columns: {missing}')
        sys.exit(1)
    else:
        print('All compatibility columns present')
        sys.exit(0)
"

# Run the compatibility check
if ! python -c "$PYTHON_CHECK"; then
    echo "Warning: Compatibility columns are missing. Running compatibility migration..."
    # Apply our custom migration for compatibility columns
    if [ -f migrations/versions/add_compatibility_columns.py ]; then
        FLASK_APP=main:app flask db upgrade add_compatibility_columns
    else
        echo "Error: Compatibility migration script not found!"
    fi
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