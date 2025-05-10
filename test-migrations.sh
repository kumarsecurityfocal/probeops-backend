#!/bin/bash
# Script to test Flask-Migrate in Docker container

set -e  # Exit on error

echo "======================================"
echo "Testing Flask-Migrate in Docker"
echo "======================================"

# Step 1: Check if Flask-Migrate is installed
echo "Step 1: Checking if Flask-Migrate is installed..."
docker compose -f docker-compose.backend.yml exec api pip freeze | grep Flask-Migrate

# Step 2: Check if migrations directory exists
echo "Step 2: Checking if migrations directory exists..."
docker compose -f docker-compose.backend.yml exec api ls -la /app/migrations

# Step 3: Test flask db commands
echo "Step 3: Testing flask db commands..."
docker compose -f docker-compose.backend.yml exec api flask db --help

# Step 4: Test migration commands
echo "Step 4: Testing migration commands..."
echo "   - Current revision:"
docker compose -f docker-compose.backend.yml exec api flask db current

echo "Step 5: Testing migration history..."
docker compose -f docker-compose.backend.yml exec api flask db history

echo "======================================"
echo "Migration tests completed"
echo "======================================"