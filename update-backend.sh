#!/bin/bash
# ProbeOps Backend Update Script
# This script rebuilds the backend Docker container and runs migrations

set -e  # Exit on error

echo "======================================"
echo "ProbeOps Backend Update Script"
echo "======================================"

# Step 1: Rebuild containers
echo "Step 1: Stopping and rebuilding containers..."
docker compose -f docker-compose.backend.yml down
docker compose -f docker-compose.backend.yml build --no-cache
docker compose -f docker-compose.backend.yml up -d

# Step 2: Wait for container to be healthy
echo "Step 2: Waiting for containers to be healthy..."
attempt=1
max_attempts=10
until [ $attempt -gt $max_attempts ]
do
    echo "Checking container health (attempt $attempt/$max_attempts)..."
    container_status=$(docker compose -f docker-compose.backend.yml ps --format json | grep -q '"Health": "healthy"' && echo "healthy" || echo "not healthy")
    
    if [ "$container_status" = "healthy" ]; then
        echo "Container is healthy!"
        break
    fi
    
    echo "Container not healthy yet, waiting..."
    sleep 5
    attempt=$((attempt+1))
done

if [ $attempt -gt $max_attempts ]; then
    echo "Error: Container failed to become healthy after multiple attempts"
    docker compose -f docker-compose.backend.yml logs api
    exit 1
fi

# Step 3: Check container status
echo "Step 3: Checking container status..."
docker compose -f docker-compose.backend.yml ps

# Step 4: Ensure database migrations are up to date
echo "Step 4: Running database migrations..."

# First try to create a migration if schema changes
echo "Generating migration for any schema changes..."
if ! docker compose -f docker-compose.backend.yml exec -T api flask db migrate -m "Auto migration from update script"; then
    echo "Warning: Migration generation failed, but continuing with upgrade"
fi

# Then apply migrations
echo "Applying migrations..."
if ! docker compose -f docker-compose.backend.yml exec -T api flask db upgrade; then
    echo "Error: Migration failed"
    docker compose -f docker-compose.backend.yml logs api
    exit 1
fi

echo "Testing API health endpoint..."
if ! curl -s http://localhost:5000/api/health | grep -q '"status":"ok"'; then
    echo "Warning: API health check failed"
    docker compose -f docker-compose.backend.yml logs api
else
    echo "API health check passed!"
fi

echo "======================================"
echo "Backend update completed successfully!"
echo "======================================"