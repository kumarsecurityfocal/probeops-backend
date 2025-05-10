#!/bin/bash
# Script to rebuild ProbeOps Docker backend container and run migrations

# Exit on error
set -e

echo "========================================"
echo "ProbeOps Docker Backend Rebuild Script"
echo "========================================"

echo "1. Stopping current containers..."
docker compose -f docker-compose.backend.yml down

echo "2. Rebuilding images with no cache..."
docker compose -f docker-compose.backend.yml build --no-cache

echo "3. Starting new containers..."
docker compose -f docker-compose.backend.yml up -d

echo "4. Waiting for containers to be healthy..."
sleep 15

echo "5. Checking container status..."
docker compose -f docker-compose.backend.yml ps

echo "6. Running database migrations..."
docker compose -f docker-compose.backend.yml exec api flask db upgrade

echo "========================================"
echo "Container rebuild completed successfully!"
echo "========================================"