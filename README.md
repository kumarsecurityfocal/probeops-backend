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

## Production Setup

### Environment Variables

Create a `.env` file with the following variables:

```
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/probeops
POSTGRES_USER=username
POSTGRES_PASSWORD=password
POSTGRES_DB=probeops
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# API Configuration
API_KEY_SECRET=your-api-key-secret
API_PORT=5000
WORKERS=4
WORKER_TIMEOUT=120
KEEPALIVE=5

# Environment
DEBUG=False
LOG_LEVEL=info
ENVIRONMENT=production
```

### Direct Deployment

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   ./start.sh
   ```

### Docker Deployment

1. Build and start the containers:
   ```
   docker-compose up -d
   ```

2. For production deployment:
   ```
   docker-compose -f docker-compose.prod.yml up -d
   ```

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

The API is configured to accept cross-origin requests with the following settings:
- All origins are allowed (`*`)
- Credentials are supported
- All standard methods (GET, POST, PUT, DELETE, OPTIONS) are allowed
- Authorization and API key headers are allowed

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
- `Dockerfile` & `docker-compose.yml`: Docker configuration
- `start.sh`: Startup script for production

## Performance Tuning

The application uses gunicorn with the following optimizations:
- **Workers**: Automatically calculated based on CPU cores (2*cores+1)
- **Worker recycling**: Workers are recycled after processing 1000 requests
- **Keepalive**: Connections are kept alive for 5 seconds
- **Timeout**: Workers timeout after 120 seconds

## Troubleshooting

- **Database Connection Issues**: Ensure PostgreSQL is running and the `DATABASE_URL` is correct
- **Authentication Problems**: Verify that `JWT_SECRET_KEY` is consistent across deployments
- **Rate Limiting**: The system limits requests to 50 per hour per user/IP