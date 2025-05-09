# ProbeOps Enhanced Startup Script

The `start.sh` script is responsible for initializing and running the ProbeOps API in a robust, production-ready manner. This document explains its features and configuration options.

## Key Features

### 1. Smart Database Connection Handling

The script includes robust database connection verification:

```bash
# Wait for the database to be ready
echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT} to be ready..."
RETRIES=0
until nc -z "${DB_HOST}" "${DB_PORT}" || [ ${RETRIES} -eq ${MAX_RETRIES} ]; do
    echo "Waiting for PostgreSQL to be available... (${RETRIES}/${MAX_RETRIES})"
    sleep ${RETRY_INTERVAL}
    RETRIES=$((RETRIES+1))
done
```

This ensures the application doesn't start until the database is available, which:
- Prevents application crashes on startup
- Makes Docker Compose deployments more reliable
- Adds resilience to network delays or database restarts

### 2. Automatic Worker Scaling

The script automatically optimizes worker count based on available CPU cores:

```bash
# Determine number of workers based on environment or CPU cores
if [ -z "${WORKERS}" ]; then
    # Calculate workers based on CPU cores if available
    if command -v nproc > /dev/null; then
        WORKERS=$(($(nproc) * 2 + 1))
        echo "Auto-configuring workers based on CPU cores: ${WORKERS}"
    else
        WORKERS=4
        echo "Using default worker count: ${WORKERS}"
    fi
fi
```

This provides:
- Optimal performance on any hardware
- No manual tuning required when scaling up
- Follows the gunicorn best practice formula (2 × cores + 1)

### 3. Worker Recycling & Memory Management

The script implements worker recycling to prevent memory leaks:

```bash
MAX_REQUESTS=${MAX_REQUESTS:-1000}
MAX_REQUESTS_JITTER=${MAX_REQUESTS_JITTER:-100}

# Start the application
exec gunicorn --workers "${WORKERS}" \
    --max-requests "${MAX_REQUESTS}" \
    --max-requests-jitter "${MAX_REQUESTS_JITTER}" \
    # Additional config here...
```

Benefits include:
- Prevents memory leaks in long-running processes
- Randomized recycling with jitter prevents all workers recycling simultaneously
- Configurable thresholds for different environments

### 4. Comprehensive Logging

The script configures proper logging for production environments:

```bash
exec gunicorn --workers "${WORKERS}" \
    # Other options...
    --log-level "${LOG_LEVEL:-info}" \
    --access-logfile - \
    --error-logfile - \
    # More options...
```

This provides:
- Configurable log levels for different environments
- Standard output/error streaming for container log capture
- Compatible with Docker logging drivers

### 5. Proxy Support

Proper handling of forwarded headers for deployments behind proxies:

```bash
exec gunicorn --workers "${WORKERS}" \
    # Other options...
    --forwarded-allow-ips "*" \
    # More options...
```

This ensures:
- Correct client IP detection behind load balancers or proxies
- Proper URL generation with the correct protocol (HTTP/HTTPS)

## Configuration Options

The script can be customized through environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKERS` | Auto (2×cores+1) | Number of gunicorn worker processes |
| `WORKER_TIMEOUT` | 120 | Request timeout in seconds |
| `KEEPALIVE` | 5 | Keep connection alive duration in seconds |
| `MAX_REQUESTS` | 1000 | Requests before worker recycling |
| `MAX_REQUESTS_JITTER` | 100 | Random jitter for recycling |
| `LOG_LEVEL` | info | Logging verbosity (debug, info, warning, error) |
| `API_PORT` | 5000 | Port to listen on |
| `DEBUG` | false | Enable debugging mode |

## Usage in Different Environments

### Development

In development, you might want to:
- Set `DEBUG=True` for verbose output
- Set `LOG_LEVEL=debug` for detailed logs
- Reduce `MAX_REQUESTS` to test worker recycling

### Production

In production, recommended settings include:
- Set `ENVIRONMENT=production`
- Set `LOG_LEVEL=info` (or `warning` for less verbose logs)
- Keep automatic worker scaling or set explicitly based on server capability
- Set `MAX_REQUESTS=1000` with `MAX_REQUESTS_JITTER=100`

## Troubleshooting

If you encounter issues with the startup script:

1. Check database connectivity with:
   ```bash
   nc -z ${DB_HOST} ${DB_PORT}
   ```

2. Verify environment variables are properly set:
   ```bash
   env | grep POSTGRES
   env | grep WORKER
   ```

3. Run with debugging enabled:
   ```bash
   DEBUG=True ./start.sh
   ```