# ProbeOps API

A modular backend system for network diagnostics with JWT authentication and PostgreSQL integration.

## Features

- **Authentication**: Secure JWT token-based authentication with support for API keys
- **Network Diagnostics**: Pure Python socket-based implementations of ping, traceroute, DNS lookup, and whois
- **Database Integration**: Persistent storage in PostgreSQL with SQLAlchemy ORM
- **Security**: Rate limiting, input sanitization, and proper CORS configuration
- **Containerization**: Complete Docker support for easy deployment

## API Endpoints

### Authentication

- `POST /users/register` - Register a new user
- `POST /users/login` - Login and get JWT token
- `GET /users/me` - Get current user information
- `GET /users` - List all users (admin only)

### API Keys

- `GET /apikeys` - List API keys for the current user
- `POST /apikeys` - Create a new API key
- `GET /apikeys/<key_id>` - Get API key details
- `PUT /apikeys/<key_id>` - Update API key
- `DELETE /apikeys/<key_id>` - Delete API key

### Network Probes

- `POST /probes/ping` - Run ping on a target host
- `POST /probes/traceroute` - Run traceroute on a target host
- `POST /probes/dns` - Run DNS lookup on a domain
- `POST /probes/whois` - Run WHOIS lookup on a domain
- `GET /probes/history` - Get probe job history for the current user

### System

- `GET /` - API root endpoint
- `GET /health` - Health check endpoint
- `GET /status` - Server status (admin only)

## Setup & Deployment

The application supports separate configurations for development and production environments. See [deployment.md](deployment.md) for detailed deployment instructions.

### Environment Configuration

We provide template environment files for both development and production:

- `.env.template` - For local development (rename to `.env`)
- `.env.backend.template` - For production (rename to `.env.backend`)

### Development Setup

```bash
# Copy development environment template
cp .env.template .env

# Edit the .env file with your desired values
nano .env

# Start development containers
docker-compose up -d
```

### Production Setup

```bash
# Copy production environment template
cp .env.backend.template .env.backend

# Edit with secure production values
nano .env.backend

# Start production backend containers
docker-compose -f docker-compose.backend.yml up -d
```

### Direct Deployment (Without Docker)

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application using the startup script:
   ```bash
   ./start.sh
   ```

The startup script includes database waiting, table creation, and automatic worker scaling based on available CPU cores.

## Frontend Integration

### Configuration

When connecting a frontend application to this API:

1. Set the API URL in your frontend .env file:
   ```
   REACT_APP_API_URL=http://172.16.0.80:5000
   ```

2. When developing locally outside of Replit, use port 3000:
   ```
   # For local development outside Replit
   PORT=3000
   ```

3. Use the following headers for authentication:
   - JWT: `Authorization: Bearer <token>`
   - API Key: `X-API-Key: <key>`

### CORS Configuration

The API is configured with comprehensive CORS support to allow direct frontend integration:

```python
CORS(
    app,
    origins="*",  # Allow all origins
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type", "Authorization", "X-API-Key", "X-Requested-With",
        "Accept", "Origin", "Access-Control-Request-Method", 
        "Access-Control-Request-Headers", "ApiKey", "Api-Key"
    ],
    supports_credentials=True,
    expose_headers=["Content-Type", "Authorization", "X-API-Key"],
    max_age=3600  # Cache preflight requests for 1 hour
)
```

Key CORS Features:
- **Universal Access**: All origins are allowed for development and testing
- **Credential Support**: Authentication works cross-origin
- **Header Flexibility**: Supports multiple API key header formats
- **Preflight Caching**: OPTIONS requests are cached for better performance
- **Comprehensive Methods**: All required HTTP methods are supported

## Development

### Database Models

The system uses the following main database models:

1. **User**: Manages user accounts
2. **ApiKey**: Handles API key generation and validation
3. **ProbeJob**: Records network diagnostic job history

### Project Structure

- `/app`: Main application package
  - `/auth`: Authentication related modules
  - `/db`: Database models and session management
  - `/probes`: Network diagnostic tools
  - `/utils`: Utility functions
- `/docs`: Documentation files
- Docker configuration:
  - `Dockerfile`: Container definition
  - `docker-compose.yml`: Development environment setup
  - `docker-compose.backend.yml`: Production backend setup
  - `.env.template`: Development environment template
  - `.env.backend.template`: Production environment template
- `start.sh`: Startup script with auto-scaling and database initialization
- Documentation:
  - `deployment.md`: Detailed deployment guide with troubleshooting
  - `docs/DEPLOYMENT_AWS.md`: AWS-specific deployment instructions
  - `docs/DOCKER_CONFIGURATION.md`: Docker configuration explanation
  - `docs/START_SCRIPT.md`: Startup script features and options

## Performance Tuning

### Gunicorn Optimizations

The enhanced `start.sh` script configures gunicorn with the following optimizations:

```bash
exec gunicorn --workers "${WORKERS}" \
    --bind "0.0.0.0:${API_PORT:-5000}" \
    --timeout "${WORKER_TIMEOUT}" \
    --keep-alive "${KEEPALIVE}" \
    --max-requests "${MAX_REQUESTS}" \
    --max-requests-jitter "${MAX_REQUESTS_JITTER}" \
    --log-level "${LOG_LEVEL:-info}" \
    --access-logfile - \
    --error-logfile - \
    --forwarded-allow-ips "*" \
    "main:app"
```

Key performance features:
- **Smart Worker Scaling**: Automatically calculated based on CPU cores (2*cores+1)
- **Worker Recycling**: Workers are recycled after processing 1000 requests to prevent memory leaks
- **Request Jitter**: Randomized recycling prevents all workers recycling simultaneously
- **Connection Keepalive**: Connections are kept alive for 5 seconds to reduce overhead
- **Configurable Timeouts**: Workers timeout after 120 seconds by default
- **Proxy Support**: Properly handles forwarded headers in production environments

## Troubleshooting

- **Database Connection Issues**: Ensure PostgreSQL is running and the `DATABASE_URL` is correct
- **Authentication Problems**: Verify that `JWT_SECRET_KEY` is consistent across deployments
- **Rate Limiting**: The system limits requests to 50 per hour per user/IP