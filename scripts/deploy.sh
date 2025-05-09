#!/usr/bin/env bash
# ProbeOps API Deployment Script
# This script is used by the CI/CD pipeline to deploy the application to a server

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error when substituting

# Default values
ENVIRONMENT="staging"
IMAGE_TAG=""
DEPLOY_PATH="/opt/probeops"
CONFIG_FILE="docker-compose.backend.yml"
RESTART_SERVICES=true
HEALTH_CHECK=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --environment|-e)
      ENVIRONMENT="$2"
      shift 2
      ;;
    --image-tag|-t)
      IMAGE_TAG="$2"
      shift 2
      ;;
    --deploy-path|-p)
      DEPLOY_PATH="$2"
      shift 2
      ;;
    --config|-c)
      CONFIG_FILE="$2"
      shift 2
      ;;
    --no-restart)
      RESTART_SERVICES=false
      shift
      ;;
    --no-health-check)
      HEALTH_CHECK=false
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --environment, -e ENV    Deployment environment (staging, production) [default: staging]"
      echo "  --image-tag, -t TAG      Docker image tag to deploy"
      echo "  --deploy-path, -p PATH   Path on the server to deploy to [default: /opt/probeops]"
      echo "  --config, -c FILE        Docker Compose configuration file [default: docker-compose.backend.yml]"
      echo "  --no-restart             Don't restart services"
      echo "  --no-health-check        Skip health check verification"
      echo "  --help, -h               Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Required parameters
if [ -z "$IMAGE_TAG" ]; then
  echo "Error: --image-tag is required"
  exit 1
fi

echo "========================================================"
echo "ProbeOps API Deployment - Environment: $ENVIRONMENT"
echo "========================================================"
echo "Image tag:    $IMAGE_TAG"
echo "Deploy path:  $DEPLOY_PATH"
echo "Config file:  $CONFIG_FILE"
echo "Restart:      $RESTART_SERVICES"
echo "Health check: $HEALTH_CHECK"
echo "========================================================"

# Create deploy directory if it doesn't exist
mkdir -p "$DEPLOY_PATH"

# Copy the configuration file
echo "Copying configuration file..."
cp "$CONFIG_FILE" "$DEPLOY_PATH/docker-compose.yml"

# Update the environment file if it exists
ENV_FILE=".env.backend"
if [ -f "$ENV_FILE" ]; then
  echo "Copying environment file..."
  # Backup existing environment file if it exists
  if [ -f "$DEPLOY_PATH/.env" ]; then
    mv "$DEPLOY_PATH/.env" "$DEPLOY_PATH/.env.backup"
  fi
  cp "$ENV_FILE" "$DEPLOY_PATH/.env"
fi

# Update Docker image tag in compose file
echo "Updating Docker image tag to $IMAGE_TAG..."
sed -i "s|probeops-api:.*$|probeops-api:$IMAGE_TAG|" "$DEPLOY_PATH/docker-compose.yml"

# Restart services if needed
if [ "$RESTART_SERVICES" = true ]; then
  echo "Restarting services..."
  cd "$DEPLOY_PATH"
  
  if [ "$ENVIRONMENT" = "production" ]; then
    # Zero-downtime deployment for production
    echo "Performing zero-downtime deployment..."
    docker-compose pull
    docker-compose up -d --no-deps --scale api=2 --no-recreate api
    sleep 10
    docker-compose up -d --force-recreate api
  else
    # Standard deployment for staging
    docker-compose pull
    docker-compose down
    docker-compose up -d
  fi
fi

# Health check if needed
if [ "$HEALTH_CHECK" = true ]; then
  echo "Performing health check..."
  RETRIES=5
  DELAY=10
  
  for i in $(seq 1 $RETRIES); do
    echo "Health check attempt $i of $RETRIES..."
    if docker exec $(docker ps -q -f name=probeops-api) curl -s http://localhost:5000/api/health | grep -q "healthy"; then
      echo "Health check passed!"
      break
    elif [ $i -eq $RETRIES ]; then
      echo "Health check failed after $RETRIES attempts"
      exit 1
    else
      echo "Health check failed, retrying in $DELAY seconds..."
      sleep $DELAY
    fi
  done
fi

echo "Deployment completed successfully!"
echo "$(date) - $ENVIRONMENT deployment of probeops-api:$IMAGE_TAG completed" >> "$DEPLOY_PATH/deployment.log"