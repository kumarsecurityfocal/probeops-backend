# AWS Deployment Guide for ProbeOps API

This guide provides detailed instructions for deploying the ProbeOps API to AWS.

## Prerequisites

- AWS account with EC2 and optionally RDS access
- SSH access to your EC2 instance
- Docker and Docker Compose installed on your EC2 instance
- Domain name (optional but recommended for production)
- Basic knowledge of AWS services

## Deployment Process

### 1. Environment Preparation

First, prepare your production environment file:

```bash
# On your AWS server after cloning the repository
git clone <your-repository-url>
cd probeops-api
cp .env.template .env.prod
nano .env.prod  # or your preferred editor
```

In the .env.prod file, configure:

- **Security settings**: Change all default secrets (JWT_SECRET_KEY, API_KEY_SECRET, POSTGRES_PASSWORD)
- **Database configuration**: Update for AWS RDS or local container
- **Environment**: Set ENVIRONMENT=production
- **Log levels**: Set LOG_LEVEL=INFO for production (or WARNING for less verbose logs)

Example .env.prod for RDS:
```
# API Configuration
API_PORT=5000
DEBUG=False

# Deployment Environment
ENVIRONMENT=production

# Security Settings
JWT_SECRET_KEY=your-secure-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60
API_KEY_SECRET=your-secure-api-key-secret

# PostgreSQL Database Configuration
POSTGRES_USER=probeops
POSTGRES_PASSWORD=your-secure-db-password
POSTGRES_DB=probeops

# For AWS RDS
DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@your-rds-endpoint.rds.amazonaws.com:5432/${POSTGRES_DB}

# Connection Pool Settings
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=300

# Log Configuration
LOG_LEVEL=INFO

# Gunicorn Server Configuration
WORKERS=4
WORKER_TIMEOUT=120
KEEPALIVE=5
```

### 2. Database Setup

#### Option A: Using AWS RDS (Recommended for Production)

1. Create a PostgreSQL RDS instance in AWS
2. Configure security groups to allow your EC2 instance to connect to RDS
3. Update your .env.prod file with the RDS endpoint:
   ```
   DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@your-rds-endpoint.rds.amazonaws.com:5432/${POSTGRES_DB}
   ```

#### Option B: Using Containerized PostgreSQL

If using the containerized PostgreSQL:
- The database container will automatically initialize when you run docker-compose
- Your data will persist in the postgres_data volume
- Make sure to set up regular backups

### 3. Docker Deployment

The production deployment uses docker-compose.prod.yml which:
- Disables volume mounts for code (uses containerized code)
- Doesn't expose the database port externally
- Has optimized resource limits
- Uses .env.prod for configuration

To deploy:

```bash
# Build the Docker images
docker-compose -f docker-compose.prod.yml build

# Start all services in detached mode
docker-compose -f docker-compose.prod.yml up -d
```

### 4. Verify Deployment

After deployment, verify everything is working:

```bash
# Check container status
docker-compose -f docker-compose.prod.yml ps

# Check application logs
docker-compose -f docker-compose.prod.yml logs -f api

# Test the health endpoint
curl http://localhost:5000/health
```

### 5. Production Security Considerations

For AWS deployment:

- **Set up a domain**: Point a domain to your EC2 instance
- **Configure Nginx**: Set up Nginx as a reverse proxy with SSL
- **Set up SSL**: Use Let's Encrypt for free SSL certificates
- **Configure AWS security groups**: Only allow traffic on necessary ports
- **Set up backup**: Configure automated database backups
- **Configure monitoring**: Set up CloudWatch alerts

#### Sample Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_session_cache shared:SSL:10m;
    
    # Proxy to your Docker service
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 6. Scaling Options

For higher traffic, you can:
- Increase WORKERS in .env.prod (e.g., set to number of CPU cores + 1)
- Adjust DB_POOL_SIZE based on expected concurrent connections
- Consider running multiple instances behind a load balancer
- Use Auto Scaling groups in AWS

### 7. Maintenance

#### Database Backups

Set up regular database backups:

```bash
# For containerized PostgreSQL
docker-compose -f docker-compose.prod.yml exec db pg_dump -U probeops probeops > backup_$(date +%Y%m%d).sql

# Add to crontab for automated backups
# 0 2 * * * cd /path/to/probeops && docker-compose -f docker-compose.prod.yml exec -T db pg_dump -U probeops probeops > backups/backup_$(date +\%Y\%m\%d).sql
```

#### Updating the Application

To update to a new version:

```bash
# Pull latest code
git pull

# Rebuild and restart containers
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml build
docker-compose -f docker-compose.prod.yml up -d

# Check logs to ensure successful startup
docker-compose -f docker-compose.prod.yml logs -f api
```

#### Monitoring

Monitor your application using:
- AWS CloudWatch for EC2 and RDS metrics
- Container logs
- Custom health checks

## Troubleshooting

### Database Connection Issues

If the API cannot connect to the database:

1. Check database logs:
   ```bash
   docker-compose -f docker-compose.prod.yml logs db
   ```

2. Verify RDS connectivity from EC2:
   ```bash
   psql -h your-rds-endpoint.rds.amazonaws.com -U probeops -d probeops
   ```

3. Check security groups and network ACLs in AWS console

### API Not Starting

If the API container isn't starting:

1. Check API logs:
   ```bash
   docker-compose -f docker-compose.prod.yml logs api
   ```

2. Verify environment variables:
   ```bash
   docker-compose -f docker-compose.prod.yml exec api env
   ```

3. Check for port conflicts:
   ```bash
   netstat -tuln | grep 5000
   ```

### SSL Certificate Issues

If SSL isn't working properly:

1. Check Nginx logs:
   ```bash
   sudo tail -f /var/log/nginx/error.log
   ```

2. Verify certificate paths and permissions
3. Test SSL configuration:
   ```bash
   curl -v https://your-domain.com/health
   ```