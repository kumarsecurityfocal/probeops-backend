# ProbeOps Docker Configuration Guide

This document explains the Docker deployment configuration for ProbeOps API in different environments.

## Configuration Files

ProbeOps uses two separate Docker Compose configurations for different environments:

1. **Development**: `docker-compose.yml` + `.env` (from `.env.template`)
2. **Production**: `docker-compose.backend.yml` + `.env.backend` (from `.env.backend.template`)

## Environment Overview

### Development Environment

The development configuration in `docker-compose.yml` provides:

- Live code reload through volume mounting
- Exposed database port (5432) for direct connection
- Debug logging
- Minimal resource constraints
- Suitable for local development and testing

### Production Environment

The production configuration in `docker-compose.backend.yml` provides:

- Containerized code (no volume mounts) for security and consistency
- No exposed database ports for improved security
- Production-level logging with larger rotation settings
- Stricter resource constraints to prevent resource exhaustion
- Security hardening with `no-new-privileges` setting
- Higher memory and CPU allocations for better performance

## Key Security Differences

| Feature | Development | Production |
|---------|-------------|------------|
| Code location | Volume mount (/app) | Container image |
| DB port exposure | External access | Internal only |
| Environment vars | .env | .env.backend |
| Security opts | Default | no-new-privileges |
| Log retention | 3 files x 10MB | 5 files x 20MB |
| Resource limits | 1 CPU, 1GB RAM | 2 CPU, 2GB RAM |

## Enhanced Start Script

The `start.sh` script includes several key features:

1. **Database Connection Verification**: Waits for PostgreSQL to be available
2. **Smart Worker Allocation**: Automatically calculates optimal worker count based on CPU cores
3. **Worker Recycling**: Prevents memory leaks with max requests and jitter settings
4. **Proxy Support**: Handles forwarded headers correctly in production
5. **Automatic Database Setup**: Creates required tables on first run

## Usage Guide

### Development Setup

```bash
# Copy and edit environment file
cp .env.template .env
nano .env

# Start development stack
docker-compose up -d
```

### Production Setup

```bash
# Copy and edit production environment file
cp .env.backend.template .env.backend
nano .env.backend

# Start production stack
docker-compose -f docker-compose.backend.yml up -d
```

## Performance Tuning

Both configurations can be tuned through environment variables:

- `WORKERS`: Number of gunicorn workers (auto-calculated if not set)
- `WORKER_TIMEOUT`: Request timeout in seconds
- `KEEPALIVE`: Connection keepalive duration
- `MAX_REQUESTS`: Worker recycle threshold
- `MAX_REQUESTS_JITTER`: Random jitter to prevent simultaneous recycling

## Troubleshooting

### Database Connection Issues
```bash
# Check if database container is running
docker-compose ps db

# Check database logs
docker-compose logs db
```

### API Container Issues
```bash
# Check API logs
docker-compose logs api

# Enter running container for debugging
docker-compose exec api bash
```

For production, use `docker-compose -f docker-compose.backend.yml` instead.