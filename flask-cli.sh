#!/bin/bash
# Flask CLI Helper Script
# This script makes it easier to run Flask CLI commands in the Docker container

# Check for docker compose command format
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    echo "Error: Neither docker-compose nor docker compose is available."
    exit 1
fi

# Set default values
COMPOSE_FILE="docker-compose.backend.yml"
FLASK_APP="main:app"
CONTAINER="api"

# Display usage information if no arguments provided
if [ $# -eq 0 ]; then
    echo "ProbeOps Flask CLI Helper"
    echo "========================="
    echo "Usage: $0 [flask-command]"
    echo ""
    echo "Examples:"
    echo "  $0 routes                  # Show all routes"
    echo "  $0 db upgrade              # Run database migrations"
    echo "  $0 db history              # Show migration history"
    echo "  $0 db migrate -m \"message\" # Create new migration"
    echo "  $0 shell                   # Start interactive shell"
    echo ""
    echo "The FLASK_APP is set to '$FLASK_APP'"
    exit 0
fi

# Prepare the Flask command with arguments
FLASK_CMD="flask --app $FLASK_APP $*"

# Display what's being executed
echo "Running in Docker container: $FLASK_CMD"

# Execute the command in the container
$DOCKER_COMPOSE -f $COMPOSE_FILE exec $CONTAINER bash -c "export FLASK_APP=$FLASK_APP && $FLASK_CMD"

# Display completion message
echo "Command completed with exit code: $?"