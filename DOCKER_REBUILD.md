# Docker Container Rebuild Process

This document outlines the process for rebuilding the Docker container for the ProbeOps API backend.

## When to Rebuild

Rebuild the Docker container when:
1. You update dependencies in `requirements.docker.txt`
2. You make changes to the Dockerfile
3. You need to reset the environment due to issues

## Automated Rebuild & Migration

Use the provided script to automatically rebuild the Docker containers and run migrations:

```bash
./update-backend.sh
```

This script will:
1. Stop existing containers
2. Rebuild with the latest code
3. Start the containers
4. Create migration files if schema changes are detected
5. Apply all pending migrations

## Migration Testing

To verify the Flask-Migrate setup is working:

```bash
./test-migrations.sh
```

## Manual Rebuild Steps

If you prefer to rebuild manually, follow these steps:

1. Stop the current containers:
```bash
docker compose -f docker-compose.backend.yml down
```

2. Rebuild the images with no cache:
```bash
docker compose -f docker-compose.backend.yml build --no-cache
```

3. Start the new containers:
```bash
docker compose -f docker-compose.backend.yml up -d
```

4. Check container status:
```bash
docker compose -f docker-compose.backend.yml ps
```

5. Create and run database migrations:
```bash
docker compose -f docker-compose.backend.yml exec api flask db migrate -m "Schema changes"
docker compose -f docker-compose.backend.yml exec api flask db upgrade
```

## Troubleshooting

### Container Won't Start
If the container fails to start, check the logs:
```bash
docker compose -f docker-compose.backend.yml logs api
```

### Database Migration Issues
If migrations fail, you might need to troubleshoot:

1. Check migration history:
```bash
docker compose -f docker-compose.backend.yml exec api flask db history
```

2. Get current migration version:
```bash
docker compose -f docker-compose.backend.yml exec api flask db current
```

3. For schema conflicts, you may need to manually modify the migration file in migrations/versions/ before upgrading.

### Missing Columns Issues
If you see errors about missing columns like `users.password_hash` or `users.is_admin`, ensure:

1. Your migration files have been created properly
2. You've run the flask db upgrade command
3. The start.sh script is properly setting FLASK_APP and running migrations

### Network Issues
If containers can't connect to each other, check the network:
```bash
docker network inspect probeops-network
```