# ProbeOps API Deployment Guide

This document outlines the steps to deploy the ProbeOps API in different environments.

## Development Deployment

For local development with hot-reloading and debugging:

1. Create your environment file:
   ```bash
   cp .env.template .env
   ```

2. Edit `.env` with your desired configuration values

3. Start the development containers:
   ```bash
   docker-compose up -d
   ```

4. Access the API at http://localhost:5000

5. View logs:
   ```bash
   docker-compose logs -f api
   ```

## Production Backend Deployment

For production deployment of the backend API:

1. Create your production environment file:
   ```bash
   cp .env.backend.template .env.backend
   ```

2. Edit `.env.backend` with secure production values
   - Ensure strong passwords are used
   - Set DEBUG=False
   - Disable any development helpers

3. Deploy using the backend-specific compose file:
   ```bash
   docker-compose -f docker-compose.backend.yml up -d
   ```

4. Check the deployment status:
   ```bash
   docker-compose -f docker-compose.backend.yml ps
   ```

5. View logs:
   ```bash
   docker-compose -f docker-compose.backend.yml logs -f api
   ```

## Environment Variables

The application behavior can be customized through environment variables:

### Critical Security Variables

- `JWT_SECRET_KEY`: Secret key for JWT token generation (MUST be strong in production)
- `API_KEY_SECRET`: Secret for API key generation (MUST be strong in production)
- `POSTGRES_PASSWORD`: Database password (MUST be strong in production)

### Performance Tuning

- `WORKERS`: Number of gunicorn workers (auto-calculated based on CPU cores if not set)
- `WORKER_TIMEOUT`: Worker timeout in seconds
- `MAX_REQUESTS`: Number of requests a worker handles before being recycled
- `KEEPALIVE`: Keepalive duration in seconds

### Database Configuration

- `POSTGRES_USER`: Database username
- `POSTGRES_PASSWORD`: Database password
- `POSTGRES_DB`: Database name
- `POSTGRES_HOST`: Database host (usually "db" in Docker Compose)
- `POSTGRES_PORT`: Database port (default: 5432)

## Security Considerations

1. **Secure Secrets**: Always use strong, unique secrets in production
2. **Database Isolation**: In production, the database is not exposed to external connections
3. **Rate Limiting**: Configured to prevent abuse of the API
4. **CORS**: Properly configured to allow only necessary origins

## Backup and Restore

To back up the PostgreSQL database:

```bash
# For development
docker-compose exec db pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup.sql

# For production
docker-compose -f docker-compose.backend.yml exec db pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup.sql
```

To restore from backup:

```bash
# For development
cat backup.sql | docker-compose exec -T db psql -U ${POSTGRES_USER} -d ${POSTGRES_DB}

# For production
cat backup.sql | docker-compose -f docker-compose.backend.yml exec -T db psql -U ${POSTGRES_USER} -d ${POSTGRES_DB}
```

## Troubleshooting

### Database Connection Issues

If the API cannot connect to the database:

1. Check if the database container is running
   ```bash
   docker-compose ps db
   ```

2. Verify database credentials in the environment file

3. Check database logs
   ```bash
   docker-compose logs db
   ```

### JWT Authentication Issues

If JWT authentication is not working:

1. Ensure `JWT_SECRET_KEY` is consistent across deployments
2. Check if token expiration (`JWT_EXPIRATION_MINUTES`) is appropriate
3. Verify that the client is sending the token in the correct format: `Authorization: Bearer <token>`

### API Performance Issues

1. Increase the number of workers
2. Adjust worker timeout settings
3. Check database query performance
4. Consider adding database indexes for frequently queried fields