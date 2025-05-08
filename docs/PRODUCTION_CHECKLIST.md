# Production Deployment Checklist

Use this checklist to ensure your ProbeOps API deployment is production-ready.

## Security

- [ ] Changed all default secrets in .env.prod
  - [ ] JWT_SECRET_KEY
  - [ ] API_KEY_SECRET
  - [ ] POSTGRES_PASSWORD

- [ ] Set up proper SSL/TLS
  - [ ] Configured Nginx or other reverse proxy
  - [ ] Obtained SSL certificates (Let's Encrypt or other provider)
  - [ ] Implemented HTTPS redirects

- [ ] Configured firewall rules
  - [ ] Limited SSH access
  - [ ] Only necessary ports exposed
  - [ ] Rate limiting at network level

- [ ] Database security
  - [ ] Strong passwords
  - [ ] No direct external access to PostgreSQL
  - [ ] Connection encryption enabled

## Configuration

- [ ] Environment variables properly set
  - [ ] ENVIRONMENT=production
  - [ ] DEBUG=False
  - [ ] LOG_LEVEL set appropriately
  - [ ] Correct database connection string

- [ ] Resource limits configured
  - [ ] Number of workers appropriate for server specs
  - [ ] Database connection pool sized correctly
  - [ ] Container resource limits set in docker-compose.prod.yml

- [ ] Used production-specific docker-compose file
  - [ ] docker-compose.prod.yml instead of docker-compose.yml
  - [ ] No volume mounts for code in production

## Monitoring & Reliability

- [ ] Health checks configured
  - [ ] Docker health checks enabled
  - [ ] External monitoring set up (e.g., AWS CloudWatch)
  - [ ] Alerts configured for critical failures

- [ ] Logging configured
  - [ ] Log rotation enabled
  - [ ] Log level set to INFO or WARNING
  - [ ] Log storage considered

- [ ] Backups configured
  - [ ] Regular PostgreSQL database backups
  - [ ] Backup verification strategy
  - [ ] Backup retention policy

- [ ] Restart policies
  - [ ] Container restart policy set to "unless-stopped"
  - [ ] System service configured for automatic restart

## Performance

- [ ] Database optimized
  - [ ] Connection pooling properly configured
  - [ ] Database indexes created for common queries

- [ ] Resource allocation
  - [ ] Adequate CPU allocation
  - [ ] Sufficient memory available
  - [ ] Disk space monitored

- [ ] Rate limiting
  - [ ] API rate limits appropriately configured
  - [ ] Distributed rate limiting if using multiple instances

## Deployment Process

- [ ] Tested .env.prod settings
  - [ ] Verified all required variables are present
  - [ ] Checked for typos and formatting errors

- [ ] Verified Docker setup
  - [ ] docker-compose.prod.yml file validated
  - [ ] Docker and Docker Compose installed on server
  - [ ] Docker daemon running

- [ ] Prepared for updates
  - [ ] Documented update procedure
  - [ ] Considered zero-downtime updates
  - [ ] Rollback strategy defined

## Validation Tests

- [ ] Basic endpoints tested
  - [ ] /health returning status 200
  - [ ] / (root) returning API information

- [ ] Authentication tested
  - [ ] User registration working
  - [ ] Login and JWT token generation working
  - [ ] API key authentication working

- [ ] Core functionality tested
  - [ ] Ping probe working
  - [ ] Traceroute probe working
  - [ ] DNS lookup working
  - [ ] WHOIS lookup working

- [ ] Edge cases tested
  - [ ] Error handling verified
  - [ ] Rate limiting correctly applied
  - [ ] Authentication failures handled properly

## Documentation

- [ ] Updated project documentation
  - [ ] API endpoints documented
  - [ ] Environment variables documented
  - [ ] Deployment procedures documented

- [ ] Created internal documentation
  - [ ] Server access information
  - [ ] Database backup procedures
  - [ ] Emergency contacts
  - [ ] Incident response procedures