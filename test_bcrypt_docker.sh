#!/bin/bash
# Test script to verify bcrypt functionality in Docker container

# Exit on error
set -e

# Output colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}ProbeOps Docker bcrypt Verification${NC}"
echo -e "${BLUE}======================================${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker.${NC}"
    exit 1
fi

# Check for required files
if [ ! -f "requirements.docker.txt" ]; then
    echo -e "${RED}Error: requirements.docker.txt not found.${NC}"
    exit 1
fi

if [ ! -f "docker-compose.backend.yml" ]; then
    echo -e "${RED}Error: docker-compose.backend.yml not found.${NC}"
    exit 1
fi

# Verify bcrypt is in requirements.docker.txt
if ! grep -q "bcrypt" requirements.docker.txt; then
    echo -e "${RED}Error: bcrypt is not in requirements.docker.txt${NC}"
    exit 1
else
    echo -e "${GREEN}✓ bcrypt is in requirements.docker.txt${NC}"
fi

# Rebuild the Docker image using the existing script
echo -e "${YELLOW}Rebuilding Docker containers...${NC}"
echo -e "${YELLOW}This may take a few minutes.${NC}"

./rebuild_docker.sh

# Check if the container is running
if ! docker compose -f docker-compose.backend.yml ps | grep -q "probeops-api" | grep -q "running"; then
    echo -e "${RED}Error: probeops-api container is not running.${NC}"
    docker compose -f docker-compose.backend.yml ps
    exit 1
fi

echo -e "${GREEN}✓ Container is running${NC}"

# Test importing bcrypt in the container
echo -e "${YELLOW}Testing bcrypt import in container...${NC}"

if docker compose -f docker-compose.backend.yml exec api python -c "import bcrypt; print('bcrypt version:', bcrypt.__version__)"; then
    echo -e "${GREEN}✓ bcrypt is successfully installed in the container${NC}"
else
    echo -e "${RED}Error: Failed to import bcrypt in the container${NC}"
    exit 1
fi

# Test Flask db commands
echo -e "${YELLOW}Testing Flask database commands...${NC}"

if docker compose -f docker-compose.backend.yml exec api flask db current; then
    echo -e "${GREEN}✓ Flask db commands work in the container${NC}"
else
    echo -e "${RED}Error: Flask db commands are not working in the container${NC}"
    exit 1
fi

echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}All tests passed successfully!${NC}"
echo -e "${BLUE}======================================${NC}"
echo -e "You can now use the container with bcrypt support."