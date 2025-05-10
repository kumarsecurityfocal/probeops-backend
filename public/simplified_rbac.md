# ProbeOps API: RBAC Implementation Summary

## Authentication Methods

1. **JWT Token Authentication**
   - Endpoint: `/api/auth/login`
   - Header: `Authorization: Bearer {token}`
   - Contains: user role + subscription tier
   - Expiration: 24 hours

2. **API Key Authentication**
   - Header: `X-API-Key: {api_key}`
   - Created via: `/api/keys` endpoint
   - Inherits creator's permissions

## User Roles

1. **User Role** (`user`)
   - Default role for registered users
   - Access to standard probe endpoints
   - Manage own API keys
   - Rate-limited by subscription tier

2. **Admin Role** (`admin`)
   - Manage all users and API keys
   - Configure rate limits
   - Access system status
   - No rate limits

## Subscription Tiers

1. **Free Tier**
   - 100 requests/day, 1,000/month
   - 15-minute interval between probes

2. **Standard Tier**
   - 500 requests/day, 5,000/month
   - 5-minute interval between probes

3. **Enterprise Tier**
   - 1,000 requests/day, 10,000/month
   - 5-minute interval between probes

## Key Frontend Implementation Components

1. **Token Storage & Validation**
2. **Role-Based UI Components**
3. **Rate Limit Displays**
4. **Error Handling for 401/403/429**
5. **Subscription Tier Management**

## Sample Code Available For

1. Login Form Implementation
2. Authenticated API Request Helper
3. Role-Based Component Rendering
4. Rate Limit Display Components

---

Full documentation available in the backend repository at `/docs/RBAC_DOCUMENTATION.md`