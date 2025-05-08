# ProbeOps API Examples

This document provides examples of API requests for the ProbeOps API using curl. These examples will help you test your deployment and integrate with the API in your applications.

## Table of Contents

1. [Health Check](#health-check)
2. [API Info](#api-info)
3. [User Registration](#user-registration)
4. [User Login](#user-login)
5. [Protected Endpoints with JWT](#protected-endpoints-with-jwt)
6. [Protected Endpoints with API Key](#protected-endpoints-with-api-key)
7. [Probe History](#probe-history)
8. [Admin Operations](#admin-operations)

## Health Check

```bash
# Simple health check
curl http://your-server:5000/health

# Expected response:
# {"status":"healthy","timestamp":"2025-05-08T01:52:00.574153"}
```

## API Info

```bash
# Get API information
curl http://your-server:5000/

# Expected response:
# {
#   "authenticated": false,
#   "endpoints": {
#     "api_keys": ["/apikeys"],
#     "auth": ["/users/register", "/users/login", "/users/me"],
#     "probes": ["/probes/ping", "/probes/traceroute", "/probes/dns", "/probes/whois", "/probes/history"]
#   },
#   "name": "ProbeOps API",
#   "status": "online",
#   "user": null,
#   "version": "1.0.0"
# }
```

## User Registration

```bash
# Register a new user
curl -X POST http://your-server:5000/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "securepassword123"
  }'

# Expected response:
# {
#   "message": "User registered successfully",
#   "user": {
#     "id": 1,
#     "username": "testuser",
#     "email": "test@example.com",
#     "is_active": true,
#     "is_admin": false,
#     "created_at": "2025-05-08T01:55:10.123456",
#     "api_key_count": 1
#   },
#   "api_key": "probe_abc123..."
# }
```

## User Login

```bash
# Login to get JWT token
curl -X POST http://your-server:5000/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "securepassword123"
  }'

# Expected response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "bearer",
#   "user": {
#     "id": 1,
#     "username": "testuser",
#     "email": "test@example.com",
#     "is_active": true,
#     "is_admin": false,
#     "created_at": "2025-05-08T01:55:10.123456",
#     "api_key_count": 1
#   }
# }
```

## Protected Endpoints with JWT

### Get User Profile

```bash
# Get current user profile with JWT authentication
# Replace YOUR_JWT_TOKEN with the token from login response
curl http://your-server:5000/users/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response:
# {
#   "user": {
#     "id": 1,
#     "username": "testuser",
#     "email": "test@example.com",
#     "is_active": true,
#     "is_admin": false,
#     "created_at": "2025-05-08T01:55:10.123456",
#     "api_key_count": 1
#   }
# }
```

### Run Ping Probe

```bash
# Run ping probe with JWT authentication
# Replace YOUR_JWT_TOKEN with the token from login response
curl -X POST http://your-server:5000/probes/ping \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "google.com",
    "count": 4
  }'

# Expected response:
# {
#   "job_id": 1,
#   "probe_type": "ping",
#   "result": "PING google.com (142.250.192.14)\nReply from 142.250.192.14: time=15.2ms\nReply from 142.250.192.14: time=14.8ms\nReply from 142.250.192.14: time=16.1ms\nReply from 142.250.192.14: time=15.5ms\n\n--- google.com ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max = 14.8/15.4/16.1 ms",
#   "success": true,
#   "target": "google.com",
#   "timestamp": "2025-05-08T01:56:10.123456"
# }
```

### Run Traceroute Probe

```bash
# Run traceroute probe with JWT authentication
# Replace YOUR_JWT_TOKEN with the token from login response
curl -X POST http://your-server:5000/probes/traceroute \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "github.com",
    "max_hops": 15
  }'

# Expected response contains the traceroute output with hop information
```

## Protected Endpoints with API Key

### DNS Lookup

```bash
# Run DNS lookup with API key authentication
# Replace YOUR_API_KEY with the API key from registration
curl -X POST http://your-server:5000/probes/dns \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "record_type": "A"
  }'

# Expected response:
# {
#   "job_id": 2,
#   "probe_type": "dns",
#   "result": "Domain: example.com\nRecord type: A\n\nA records found:\n93.184.216.34\n\nQuery time: 45ms",
#   "success": true,
#   "target": "example.com",
#   "timestamp": "2025-05-08T01:57:10.123456"
# }
```

### WHOIS Lookup

```bash
# Run WHOIS lookup with API key authentication
# Replace YOUR_API_KEY with the API key from registration
curl -X POST http://your-server:5000/probes/whois \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "github.com"
  }'

# Expected response contains WHOIS information for the domain
```

## Probe History

```bash
# Get history of probe jobs (authenticated)
# Replace YOUR_JWT_TOKEN with the token from login response
curl http://your-server:5000/probes/history \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response:
# {
#   "items": [
#     {
#       "id": 2,
#       "probe_type": "dns",
#       "target": "example.com",
#       "parameters": "{\"record_type\":\"A\"}",
#       "result": "Domain: example.com\nRecord type: A\n\nA records found:\n93.184.216.34\n\nQuery time: 45ms",
#       "success": true,
#       "created_at": "2025-05-08T01:57:10.123456"
#     },
#     {
#       "id": 1,
#       "probe_type": "ping",
#       "target": "google.com",
#       "parameters": "{\"count\":4}",
#       "result": "PING google.com (142.250.192.14)\nReply from 142.250.192.14: time=15.2ms\nReply from 142.250.192.14: time=14.8ms\nReply from 142.250.192.14: time=16.1ms\nReply from 142.250.192.14: time=15.5ms\n\n--- google.com ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max = 14.8/15.4/16.1 ms",
#       "success": true,
#       "created_at": "2025-05-08T01:56:10.123456"
#     }
#   ],
#   "page": 1,
#   "pages": 1,
#   "total": 2,
#   "next": null,
#   "prev": null
# }
```

### Pagination and Filtering

```bash
# Get paginated history with filters
curl "http://your-server:5000/probes/history?page=1&per_page=10&probe_type=ping" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response includes pagination information and filtered items
```

## Admin Operations

### List All Users (Admin Only)

```bash
# List all users (requires admin privileges)
# Replace ADMIN_JWT_TOKEN with an admin user's JWT token
curl http://your-server:5000/users \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"

# Expected response includes a list of all users
```

### Server Status (Admin Only)

```bash
# Get server status information (requires admin privileges)
# Replace ADMIN_JWT_TOKEN with an admin user's JWT token
curl http://your-server:5000/server/status \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"

# Expected response includes server status information
```

## API Key Management

### List API Keys

```bash
# List all API keys for the current user
# Replace YOUR_JWT_TOKEN with the token from login response
curl http://your-server:5000/apikeys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response includes a list of API keys for the current user
```

### Create New API Key

```bash
# Create a new API key
# Replace YOUR_JWT_TOKEN with the token from login response
curl -X POST http://your-server:5000/apikeys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "My Test API Key"
  }'

# Expected response includes the newly created API key
```

### Delete API Key

```bash
# Delete an API key
# Replace YOUR_JWT_TOKEN with the token from login response
# Replace API_KEY_ID with the ID of the API key to delete
curl -X DELETE http://your-server:5000/apikeys/API_KEY_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected response confirms the deletion
```