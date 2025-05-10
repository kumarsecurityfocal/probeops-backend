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
sleep 15  # Give it some time to start

# Step 3: Check container status
echo "Step 3: Checking container status..."
docker compose -f docker-compose.backend.yml ps

# Step 4: Ensure database migrations are up to date
echo "Step 4: Running database migrations..."
docker compose -f docker-compose.backend.yml exec api flask db migrate -m "Auto migration from update script"
docker compose -f docker-compose.backend.yml exec api flask db upgrade

echo "======================================"
echo "Backend update completed successfully!"
echo "======================================"