# Docker Container Rebuild Process

This document outlines the process for rebuilding the Docker container for the ProbeOps API backend.

## When to Rebuild

Rebuild the Docker container when:
1. You update dependencies in `requirements.docker.txt`
2. You make changes to the Dockerfile
3. You need to reset the environment due to issues

## Automated Rebuild

Use the provided script to automatically rebuild the Docker containers:

```bash
./rebuild_docker.sh
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

5. Run database migrations:
```bash
docker compose -f docker-compose.backend.yml exec api flask db upgrade
```

## Troubleshooting

### Container Won't Start
If the container fails to start, check the logs:
```bash
docker compose -f docker-compose.backend.yml logs api
```

### Database Migration Issues
If migrations fail, you may need to create a new migration:
```bash
docker compose -f docker-compose.backend.yml exec api flask db migrate -m "description"
docker compose -f docker-compose.backend.yml exec api flask db upgrade
```

### Network Issues
If containers can't connect to each other, check the network:
```bash
docker network inspect probeops-network
```