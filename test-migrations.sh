#!/bin/bash
# ProbeOps Migration Test Script
# This script validates the migration process without rebuilding containers

set -e  # Exit on error

echo "======================================"
echo "ProbeOps Migration Test Script"
echo "======================================"

# Check if the API container is running
container_id=$(docker compose -f docker-compose.backend.yml ps -q api)
if [ -z "$container_id" ]; then
    echo "API container not running. Start it with docker compose -f docker-compose.backend.yml up -d"
    exit 1
fi

# Set FLASK_APP environment variable
echo "Setting up environment in container..."
docker compose -f docker-compose.backend.yml exec -T api bash -c 'export FLASK_APP=probeops.app'

# Generate migration
echo "Attempting to generate migration..."
docker compose -f docker-compose.backend.yml exec -T api flask db migrate -m "Test migration $(date +%Y%m%d%H%M%S)"

# Show migrations
echo "Listing migrations..."
docker compose -f docker-compose.backend.yml exec -T api flask db show

# Apply migrations
echo "Applying migrations..."
docker compose -f docker-compose.backend.yml exec -T api flask db upgrade

# Verify database schema
echo "Verifying database schema..."
docker compose -f docker-compose.backend.yml exec -T api flask db check

# Test database access via the API
echo "Testing database access via health endpoint..."
curl -s http://localhost:5000/api/health | grep -q '"status":"ok"' && \
    echo "API health check passed!" || \
    echo "API health check failed!"

echo "======================================"
echo "Migration test completed!"
echo "======================================"