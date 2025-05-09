# ProbeOps API CI/CD Pipeline

This document explains the continuous integration and continuous deployment (CI/CD) pipeline for the ProbeOps API.

## Overview

The CI/CD pipeline automatically tests, builds, and deploys the ProbeOps API to staging and production environments. The pipeline is implemented using GitHub Actions and is defined in the `.github/workflows/cicd.yml` file.

```
Code Changes → Tests → Build → Deploy to Staging → Deploy to Production
```

## Pipeline Stages

### 1. Testing

The testing stage runs various tests to ensure code quality and functionality:

- **Linting**: Checks code style and quality using flake8
- **Unit Tests**: Runs unit tests using pytest
- **Coverage Report**: Generates test coverage reports

This stage is run on every push to the repository and for all pull requests.

### 2. Building

The building stage creates a Docker image for the application:

- Builds the Docker image using the Dockerfile
- Tags the image with the Git SHA and branch name
- Pushes the image to GitHub Container Registry (ghcr.io)

This stage runs after the testing stage is successful.

### 3. Deployment to Staging

The deployment to staging stage deploys the application to the staging environment:

- Automatically triggered after successful build for pushes to `develop`, `main`, and `master` branches
- Can also be manually triggered using workflow_dispatch
- Uses SSH to deploy to the staging server
- Copies the Docker Compose configuration and environment files
- Pulls the latest Docker image and updates the configuration
- Restarts the services
- Verifies the deployment with a health check

### 4. Deployment to Production

The deployment to production stage deploys the application to the production environment:

- Manually triggered using workflow_dispatch with environment=production
- Uses SSH to deploy to the production server
- Performs a zero-downtime deployment to minimize disruption
- Verifies the deployment with a health check

## GitHub Secrets

The following secrets need to be configured in GitHub:

- `AWS_ACCESS_KEY_ID`: AWS access key for the deployment
- `AWS_SECRET_ACCESS_KEY`: AWS secret key for the deployment
- `SSH_PRIVATE_KEY`: SSH private key for accessing the deployment servers
- `SSH_KNOWN_HOSTS`: SSH known hosts for secure connections
- `DEPLOY_HOST`: Hostname or IP address of the deployment server
- `DEPLOY_USER`: Username for SSH connection to the deployment server

## Environments

The pipeline uses GitHub Environments for different deployment targets:

- **staging**: For deploying to the staging environment
- **production**: For deploying to the production environment

These environments can have specific approval rules and protection settings in GitHub.

## Manual Deployment

You can also manually deploy the application using the deployment script:

```bash
./scripts/deploy.sh \
  --environment production \
  --image-tag sha-12345678 \
  --deploy-path /opt/probeops
```

See `./scripts/deploy.sh --help` for more options.

## Monitoring Deployments

The deployment script creates a log file at `/opt/probeops/deployment.log` on the server with a record of all deployments.

You can view the logs of the GitHub Actions workflows in the "Actions" tab of the GitHub repository.

## Troubleshooting

If a deployment fails, check the GitHub Actions logs for detailed information about the failure.

Common issues:
- SSH connection problems: Check SSH keys and known hosts
- Docker permissions: Ensure the deploy user has permissions to run Docker commands
- Health check failures: Check the logs of the application container