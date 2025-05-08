# ProbeOps API Deployment Guide

This guide explains how to deploy the ProbeOps API using Docker in both development and production environments.

## Prerequisites

- Docker and Docker Compose
- Git (for cloning the repository)
- Basic knowledge of command line operations

## Development Deployment

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd probeops-api
   ```

2. **Set up environment configuration:**
   ```bash
   # Copy the environment template
   cp .env.template .env
   
   # Edit .env with your desired configuration
   # Be sure to set strong passwords for production use
   ```

3. **Build and start the services:**
   ```bash
   docker-compose build
   docker-compose up -d
   ```

4. **Check the logs to ensure everything is running correctly:**
   ```bash
   docker-compose logs -f
   ```

5. **Access the API:**
   - The API will be available at: `http://localhost:5000`
   - Health check endpoint: `http://localhost:5000/health`

## Production Deployment

For production environments, we recommend using the production-specific Docker Compose file:

1. **Create a production environment file:**
   ```bash
   cp .env.template .env.prod
   
   # Edit .env.prod with production-specific settings
   # Make sure to set secure passwords and configuration
   ```

2. **Build and deploy using the production configuration:**
   ```bash
   docker-compose -f docker-compose.prod.yml build
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Verify deployment:**
   ```bash
   docker-compose -f docker-compose.prod.yml ps
   docker-compose -f docker-compose.prod.yml logs -f
   ```

## Important Security Considerations

1. **Change Default Secrets:**
   - Set strong passwords for database
   - Generate unique JWT and API key secrets
   - Use environment-specific configurations

2. **Database Security:**
   - In production, do not expose the database port externally
   - Use a separate database backup strategy
   - Consider using a managed database service for production

3. **API Access:**
   - Set up a reverse proxy (Nginx, Traefik) with TLS for production
   - Implement proper network security (firewalls, etc.)
   - Use rate limiting to prevent abuse

## Monitoring and Maintenance

1. **Logs:**
   - Docker logs are configured with rotation to prevent disk space issues
   - Consider setting up a centralized logging solution for production

2. **Backups:**
   - Set up regular database backups:
     ```bash
     docker-compose exec db pg_dump -U probeops probeops > backup_$(date +%Y%m%d).sql
     ```

3. **Updates:**
   - Regularly update dependencies and the base images
   - Use rolling updates to minimize downtime

## Common Issues and Troubleshooting

1. **Database Connection Issues:**
   - Ensure PostgreSQL is running: `docker-compose ps`
   - Check database logs: `docker-compose logs db`
   - Verify connection settings in `.env` file

2. **API Not Starting:**
   - Check API logs: `docker-compose logs api`
   - Ensure database migrations completed successfully
   - Verify environment variables are set correctly

3. **Performance Issues:**
   - Adjust worker count based on available resources
   - Monitor resource usage: `docker stats`
   - Consider scaling horizontally for high-load environments

## Customizing the Deployment

1. **Custom Port:**
   - Change the `API_PORT` in your `.env` file

2. **Worker Configuration:**
   - Adjust `WORKERS` count based on your CPU cores
   - Set `WORKER_TIMEOUT` based on expected request duration

3. **Database Tuning:**
   - Adjust connection pool settings in `.env` file
   - Customize PostgreSQL configuration as needed

For more information and advanced configuration options, refer to the project documentation.