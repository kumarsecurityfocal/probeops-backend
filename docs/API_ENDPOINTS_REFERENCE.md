# ProbeOps API Endpoints Reference

This document provides a comprehensive reference of all available endpoints in the ProbeOps API. It includes details on request/response formats, authentication requirements, and examples.

## Base URL

All API endpoints are prefixed with `/api`

## Authentication

The API supports two authentication methods:

1. **JWT Token Authentication**
   - Include the token in the `Authorization` header: `Authorization: Bearer {token}`
   - Used for interactive user sessions
   - Obtain via `/api/users/login` endpoint

2. **API Key Authentication**
   - Include the API key in the `X-API-Key` header: `X-API-Key: {api_key}`
   - Used for automated/machine access
   - Obtain via `/api/apikeys` endpoint (requires JWT authentication)

## API Endpoints

### Health Check

#### GET `/api/health`

Check if the API is running properly.

**Authentication Required:** No

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-05-10T15:15:30.123456"
}
```

### Authentication Endpoints

#### POST `/api/users/register`

Register a new user.

**Authentication Required:** No

**Request:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 3,
    "username": "newuser",
    "email": "user@example.com",
    "is_active": true,
    "role": "user",
    "subscription_tier": "Free",
    "created_at": "2025-05-10T15:20:00.123456"
  }
}
```

#### POST `/api/users/login`

Login and get a JWT token.

**Authentication Required:** No

**Request:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 3,
    "username": "newuser",
    "email": "user@example.com",
    "is_active": true,
    "role": "user",
    "subscription_tier": "Free",
    "created_at": "2025-05-10T15:20:00.123456"
  }
}
```

#### GET `/api/users/me`

Get current user information.

**Authentication Required:** Yes (JWT)

**Response:**
```json
{
  "id": 3,
  "username": "newuser",
  "email": "user@example.com",
  "is_active": true,
  "role": "user",
  "subscription_tier": "Free",
  "created_at": "2025-05-10T15:20:00.123456"
}
```

### Network Probe Endpoints

#### POST `/api/probes/ping`

Run ping against a target host.

**Authentication Required:** Yes (JWT or API Key)

**Request:**
```json
{
  "host": "google.com",
  "count": 4
}
```

**Response:**
```json
{
  "success": true,
  "probe_type": "ping",
  "target": "google.com",
  "result": "PING google.com (142.250.186.78)\nResolving to IP: 142.250.186.78\n\n64 bytes from 142.250.186.78: icmp_seq=0 time=15.45 ms\n64 bytes from 142.250.186.78: icmp_seq=1 time=14.32 ms\n64 bytes from 142.250.186.78: icmp_seq=2 time=16.78 ms\n64 bytes from 142.250.186.78: icmp_seq=3 time=15.11 ms\n\n--- google.com ping statistics ---\n4 packets transmitted, 4 received, 0.0% packet loss\nrtt min/avg/max = 14.320/15.415/16.780 ms",
  "timestamp": "2025-05-10T15:25:00.123456",
  "job_id": 1
}
```

#### POST `/api/probes/traceroute`

Run traceroute to a target host.

**Authentication Required:** Yes (JWT or API Key)

**Request:**
```json
{
  "host": "github.com",
  "max_hops": 15
}
```

**Response:**
```json
{
  "success": true,
  "probe_type": "traceroute",
  "target": "github.com",
  "result": "traceroute to github.com (140.82.121.3), 15 hops max\nTracing route to github.com [140.82.121.3]\n\n 1  192.168.1.1  1.234 ms\n 2  10.10.10.1 (10.10.10.1)  5.678 ms\n 3  172.16.0.1 (172.16.0.1)  10.123 ms\n...\n15  140.82.121.3 (140.82.121.3)  45.678 ms\n\nTrace complete.",
  "timestamp": "2025-05-10T15:26:00.123456",
  "job_id": 2
}
```

#### POST `/api/probes/dns`

Run DNS lookup on a domain.

**Authentication Required:** Yes (JWT or API Key)

**Request:**
```json
{
  "domain": "example.com",
  "record_type": "A"
}
```

**Response:**
```json
{
  "success": true,
  "probe_type": "dns",
  "target": "example.com",
  "result": ";; QUESTION SECTION:\n;example.com.\t\tIN\tA\n\n;; ANSWER SECTION:\nexample.com.\t\tIN\tA\t93.184.216.34\n\n;; Query time: 45 msec\n;; SERVER: 8.8.8.8#53\n;; WHEN: Sat May 10 15:27:00 2025",
  "timestamp": "2025-05-10T15:27:00.123456",
  "job_id": 3
}
```

#### POST `/api/probes/whois`

Run WHOIS lookup on a domain.

**Authentication Required:** Yes (JWT or API Key)

**Request:**
```json
{
  "domain": "github.com"
}
```

**Response:**
```json
{
  "success": true,
  "probe_type": "whois",
  "target": "github.com",
  "result": "WHOIS lookup for domain: github.com\n\nDomain Information:\n  Domain: github.com\n  IP Address: 140.82.121.3\n\nDNS Information:\n  A Records:\n    140.82.121.3\n  Name Servers:\n    ns-1707.awsdns-21.co.uk\n    ns-422.awsdns-52.com\n    ...",
  "timestamp": "2025-05-10T15:28:00.123456",
  "job_id": 4
}
```

#### GET `/api/probes/history`

Get probe job history for the current user.

**Authentication Required:** Yes (JWT)

**Query Parameters:**
- `limit` (optional): Maximum number of results to return (default: 10, max: 100)
- `offset` (optional): Number of results to skip (for pagination)

**Response:**
```json
{
  "jobs": [
    {
      "id": 4,
      "probe_type": "whois",
      "target": "github.com",
      "parameters": "{}",
      "success": true,
      "created_at": "2025-05-10T15:28:00.123456"
    },
    {
      "id": 3,
      "probe_type": "dns",
      "target": "example.com",
      "parameters": "{\"record_type\":\"A\"}",
      "success": true,
      "created_at": "2025-05-10T15:27:00.123456"
    },
    {
      "id": 2,
      "probe_type": "traceroute",
      "target": "github.com",
      "parameters": "{\"max_hops\":15}",
      "success": true,
      "created_at": "2025-05-10T15:26:00.123456"
    },
    {
      "id": 1,
      "probe_type": "ping",
      "target": "google.com",
      "parameters": "{\"count\":4}",
      "success": true,
      "created_at": "2025-05-10T15:25:00.123456"
    }
  ],
  "pagination": {
    "total": 4,
    "limit": 10,
    "offset": 0,
    "next": null,
    "previous": null
  }
}
```

### API Key Management

#### GET `/api/apikeys`

List API keys for current user.

**Authentication Required:** Yes (JWT)

**Response:**
```json
{
  "api_keys": [
    {
      "id": 1,
      "key": "probeops.8f7d6e5c4b3a2910...",
      "description": "My First API Key",
      "is_active": true,
      "created_at": "2025-05-10T15:30:00.123456",
      "last_used_at": "2025-05-10T15:35:00.123456"
    }
  ]
}
```

#### POST `/api/apikeys`

Create a new API key.

**Authentication Required:** Yes (JWT)

**Request:**
```json
{
  "description": "My Development API Key"
}
```

**Response:**
```json
{
  "message": "API key created successfully",
  "api_key": {
    "id": 2,
    "key": "probeops.1a2b3c4d5e6f7g8h...",
    "description": "My Development API Key",
    "is_active": true,
    "created_at": "2025-05-10T15:40:00.123456",
    "last_used_at": null
  }
}
```

#### DELETE `/api/apikeys/{key_id}`

Delete an API key.

**Authentication Required:** Yes (JWT)

**Response:**
```json
{
  "message": "API key deleted successfully"
}
```

### Admin Endpoints

#### GET `/api/admin/users`

List all users (admin only).

**Authentication Required:** Yes (JWT)
**Required Role:** admin

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@probeops.com",
      "role": "admin",
      "subscription_tier": "Enterprise",
      "is_active": true,
      "created_at": "2025-05-10T00:00:00.000000",
      "api_key_count": 1,
      "probe_job_count": 10
    },
    {
      "id": 2,
      "username": "standard",
      "email": "standard@probeops.com",
      "role": "user",
      "subscription_tier": "Standard",
      "is_active": true,
      "created_at": "2025-05-10T00:00:00.000000",
      "api_key_count": 2,
      "probe_job_count": 15
    },
    {
      "id": 3,
      "username": "newuser",
      "email": "user@example.com",
      "role": "user",
      "subscription_tier": "Free",
      "is_active": true,
      "created_at": "2025-05-10T15:20:00.123456",
      "api_key_count": 2,
      "probe_job_count": 4
    }
  ]
}
```

#### POST `/api/admin/users/{user_id}/role`

Update user role (admin only).

**Authentication Required:** Yes (JWT)
**Required Role:** admin

**Request:**
```json
{
  "role": "admin"
}
```

**Response:**
```json
{
  "message": "User role updated successfully",
  "user": {
    "id": 3,
    "username": "newuser",
    "email": "user@example.com",
    "role": "admin",
    "subscription_tier": "Free",
    "is_active": true
  }
}
```

#### POST `/api/admin/users/{user_id}/tier`

Update user subscription tier (admin only).

**Authentication Required:** Yes (JWT)
**Required Role:** admin

**Request:**
```json
{
  "subscription_tier": "Enterprise"
}
```

**Response:**
```json
{
  "message": "User subscription tier updated successfully",
  "user": {
    "id": 3,
    "username": "newuser",
    "email": "user@example.com",
    "role": "admin",
    "subscription_tier": "Enterprise",
    "is_active": true
  }
}
```

#### GET `/api/admin/status`

Get server status (admin only).

**Authentication Required:** Yes (JWT)
**Required Role:** admin

**Response:**
```json
{
  "system": {
    "version": "1.0.0",
    "uptime": "5d 12h 30m",
    "memory_usage": "512MB / 2GB",
    "cpu_usage": "15%"
  },
  "database": {
    "status": "connected",
    "size": "128MB",
    "users_count": 3,
    "api_keys_count": 5,
    "probe_jobs_count": 29
  },
  "requests": {
    "total_today": 120,
    "total_this_month": 1500,
    "average_response_time": "150ms"
  }
}
```

## Error Responses

The API uses standard HTTP status codes to indicate the success or failure of requests:

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions (wrong role or tier)
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

Error responses include a JSON object with error details:

```json
{
  "error": "Unauthorized",
  "message": "Authentication required"
}
```

## Rate Limiting

Rate limits are applied based on the user's subscription tier. The API includes the following headers in responses:

```
X-RateLimit-Limit-Day: 100
X-RateLimit-Remaining-Day: 95
X-RateLimit-Limit-Month: 1000
X-RateLimit-Remaining-Month: 980
X-RateLimit-Reset: 1672531200
```

When a rate limit is exceeded, the API returns a `429 Too Many Requests` response with information about when the limit will reset.