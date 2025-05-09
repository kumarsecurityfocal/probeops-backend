# Internal Testing Guide for ProbeOps API

This document provides guidance for internal testing of the ProbeOps API and CI/CD pipeline.

## Local Testing

Before pushing code to the repository, you should run tests locally to ensure your changes work correctly.

### Running Unit Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/
```

### Running the API Locally

```bash
# Start the Flask server
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

The API will be available at http://localhost:5000/

## CI/CD Pipeline

The CI/CD pipeline is implemented using GitHub Actions and is defined in `.github/workflows/cicd.yml`.

### Pipeline Stages

1. **Testing**: Runs automated tests against your code
2. **Building**: Builds a Docker image for the application
3. **Deployment to Staging**: Deploys to the staging environment
4. **Deployment to Production**: Deploys to the production environment (manual trigger)

### Testing the CI/CD Pipeline

You can test different aspects of the CI/CD pipeline:

#### Testing the Build Process

1. Push a commit to any branch of the repository
2. The testing stage will automatically run
3. If you push to `develop`, `main`, or `master`, the build stage will also run

#### Testing Deployment to Staging

1. Push a commit to the `develop`, `main`, or `master` branch
2. The CI/CD pipeline will automatically deploy to staging
3. Verify the deployment by checking the staging environment

#### Testing Manual Deployment

1. Go to the "Actions" tab in GitHub
2. Select the "ProbeOps API CI/CD" workflow
3. Click "Run workflow"
4. Select the branch to deploy and choose the "staging" environment
5. Click "Run workflow"
6. Verify the deployment in the staging environment

### Verifying Deployments

After a deployment, verify the application is working correctly:

```bash
# Check if the service is running
curl https://staging-api.probeops.com/api/health

# Test login (replace with actual credentials)
curl -X POST https://staging-api.probeops.com/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpassword"}'

# Test protected endpoints with token (replace TOKEN with actual token)
curl https://staging-api.probeops.com/api/users/me \
  -H "Authorization: Bearer TOKEN"

# Test protected endpoints with API key (replace API_KEY with actual key)
curl https://staging-api.probeops.com/api/probes/history \
  -H "X-API-Key: API_KEY"
```

## Monitoring Deployments

You can monitor the status of deployments in several ways:

1. **GitHub Actions**: Check the "Actions" tab in GitHub for detailed logs
2. **Deployment Logs**: Access `/opt/probeops/deployment.log` on the server
3. **Application Logs**: Check the Docker container logs

```bash
# SSH to the server
ssh user@staging-server

# View deployment logs
cat /opt/probeops/deployment.log

# View container logs
docker logs probeops-api
```

## Setting Up GitHub Secrets

For the CI/CD pipeline to work correctly, the following secrets must be set in GitHub:

1. Go to your repository on GitHub
2. Click "Settings" → "Secrets and variables" → "Actions"
3. Add the following secrets:

- `AWS_ACCESS_KEY_ID`: AWS access key for deployment
- `AWS_SECRET_ACCESS_KEY`: AWS secret key for deployment
- `SSH_PRIVATE_KEY`: SSH private key for accessing the deployment servers
- `SSH_KNOWN_HOSTS`: SSH known hosts for secure connections
- `DEPLOY_HOST`: Hostname or IP address of the staging server
- `DEPLOY_USER`: Username for SSH connection to the staging server
- `PROD_DEPLOY_HOST`: Hostname or IP address of the production server
- `PROD_DEPLOY_USER`: Username for SSH connection to the production server

## Troubleshooting

### Common Issues

#### 1. Tests Failing

If tests are failing in the CI pipeline:

1. Check the GitHub Actions logs for details
2. Run the tests locally to reproduce the issue
3. Fix the issues and push again

#### 2. Build Failing

If the build stage is failing:

1. Check the Dockerfile and make sure it's valid
2. Try building the Docker image locally: `docker build -t probeops-api:local .`
3. Fix any issues and push again

#### 3. Deployment Failing

If deployment is failing:

1. Check the GitHub Actions logs for details
2. Verify the server is accessible
3. Check SSH credentials and permissions
4. Verify Docker is installed and running on the server

#### 4. Application Not Working After Deployment

If the application is deployed but not working:

1. Check the container logs: `docker logs probeops-api`
2. Verify the environment variables are correctly set
3. Check the health check endpoint: `/api/health`
4. Verify the database connection

## Integration Testing

For thorough testing of the API, you can use the following scripts:

### Testing Authentication

```bash
#!/bin/bash
# test_auth.sh

BASE_URL="https://staging-api.probeops.com/api"

# Test registration
echo "Testing registration..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/users/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"testpassword"}')
echo $REGISTER_RESPONSE

# Test login
echo "Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/users/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpassword"}')
echo $LOGIN_RESPONSE

# Extract token
TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Test user info
echo "Testing user info..."
curl -s "$BASE_URL/users/me" \
  -H "Authorization: Bearer $TOKEN"

# Test API key creation
echo "Testing API key creation..."
API_KEY_RESPONSE=$(curl -s -X POST "$BASE_URL/apikeys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"description":"Test API Key"}')
echo $API_KEY_RESPONSE

# Extract API key
API_KEY=$(echo $API_KEY_RESPONSE | grep -o '"key":"[^"]*' | cut -d'"' -f4)

# Test API key authentication
echo "Testing API key authentication..."
curl -s "$BASE_URL/probes/history" \
  -H "X-API-Key: $API_KEY"
```

### Testing Network Probes

```bash
#!/bin/bash
# test_probes.sh

BASE_URL="https://staging-api.probeops.com/api"
API_KEY="your_api_key_here"

# Test ping probe
echo "Testing ping probe..."
curl -s -X POST "$BASE_URL/probes/ping" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host":"example.com","count":4}'

# Test traceroute probe
echo "Testing traceroute probe..."
curl -s -X POST "$BASE_URL/probes/traceroute" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host":"example.com","max_hops":15}'

# Test DNS probe
echo "Testing DNS probe..."
curl -s -X POST "$BASE_URL/probes/dns" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","record_type":"A"}'

# Test WHOIS probe
echo "Testing WHOIS probe..."
curl -s -X POST "$BASE_URL/probes/whois" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'

# Test probe history
echo "Testing probe history..."
curl -s "$BASE_URL/probes/history" \
  -H "X-API-Key: $API_KEY"
```

## Load Testing

For load testing the API, you can use tools like Apache Benchmark (ab) or JMeter.

### Example with Apache Benchmark

```bash
# Install Apache Benchmark
apt-get install apache2-utils

# Test the health endpoint (100 requests, 10 concurrent)
ab -n 100 -c 10 https://staging-api.probeops.com/api/health

# Test ping endpoint with API key (50 requests, 5 concurrent)
ab -n 50 -c 5 -p ping_payload.json -T "application/json" \
  -H "X-API-Key: your_api_key_here" \
  https://staging-api.probeops.com/api/probes/ping

# Where ping_payload.json contains:
# {"host":"example.com","count":4}
```

## Security Testing

For security testing, consider the following:

1. **Input Validation**: Test with malicious input to ensure proper sanitization
2. **Authentication**: Test with invalid tokens/keys to ensure proper rejection
3. **Rate Limiting**: Test with excessive requests to ensure rate limiting works
4. **CORS**: Test from unauthorized origins to ensure CORS protection works

## Conclusion

This guide should help you test the ProbeOps API and CI/CD pipeline effectively. If you encounter any issues not covered in this guide, please contact the DevOps team for assistance.