# Testing the Backend via Internal Docker Network

## Internal Network-Only Configuration

The ProbeOps API backend is configured to run exclusively on the internal Docker network in production, with no public IP exposure. This improves security by preventing direct access to the API except through approved frontend services.

## Testing the Backend Internally

To test the backend API from another container within the same Docker network:

### 1. Using curl from a utility container

```bash
# Run a temporary container on the same network
docker run --rm -it --network probeops-network alpine sh

# Install curl
apk add --no-cache curl

# Test the health endpoint
curl -v http://probeops-api:5000/api/health

# Test other endpoints (with authentication if needed)
curl -v http://probeops-api:5000/api/
```

### 2. From another service container

If you have another service (e.g., frontend) in the Docker Compose setup, you can add a command to test connectivity:

```yaml
services:
  frontend:
    # ... frontend configuration ...
    command: sh -c "sleep 10 && curl -v http://probeops-api:5000/api/health && node server.js"
```

### 3. Using docker-compose exec

You can execute curl commands within the running API container itself:

```bash
# Execute curl within the API container
docker-compose -f docker-compose.backend.yml exec api curl -v http://localhost:5000/api/health
```

## Key Points About Internal-Only Configuration

1. **Service Discovery**: Within the Docker network, containers can communicate using their service names (e.g., `probeops-api`) as hostnames.

2. **No Port Exposure**: The backend service doesn't expose any ports to the host in production mode.

3. **Proxy Configuration**: In production, a reverse proxy (such as NGINX) should handle public-facing traffic and forward requests to the API container through the Docker network.

4. **Security**: This configuration enhances security by minimizing the attack surface, as the API is only accessible to approved services within the same network.

## Reverse Proxy Example

For production deployments, configure a reverse proxy like this:

```
server {
    listen 443 ssl;
    server_name api.probeops.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://probeops-api:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

This setup ensures all public requests go through the secured proxy while the backend API remains isolated within the Docker network.