# ProbeOps API: RBAC Implementation Documentation

This document provides comprehensive information about the Role-Based Access Control (RBAC) implementation in the ProbeOps API. This documentation is intended for frontend developers to understand how to integrate with the backend RBAC system.

## Table of Contents

1. [Authentication Methods](#authentication-methods)
2. [User Roles](#user-roles)
3. [Subscription Tiers](#subscription-tiers)
4. [Rate Limiting](#rate-limiting)
5. [API Endpoints](#api-endpoints)
6. [Frontend Integration Guidelines](#frontend-integration-guidelines)
7. [Implementation Examples](#implementation-examples)

## Authentication Methods

The ProbeOps API supports two authentication methods:

### JWT Token Authentication

- Used for interactive user sessions
- Tokens are obtained through the `/api/auth/login` endpoint
- Tokens contain user information including role and subscription tier
- Tokens expire after 24 hours by default
- Must be included in the `Authorization` header as `Bearer {token}`

Example request:
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "secure_password"
}
```

Example response:
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "user@example.com",
    "email": "user@example.com",
    "role": "user",
    "subscription_tier": "Free",
    "is_active": true,
    "created_at": "2023-01-01T00:00:00Z"
  }
}
```

### API Key Authentication

- Used for machine-to-machine communication
- Keys are obtained through the `/api/keys` endpoint (requires JWT authentication)
- Must be included in the `X-API-Key` header
- API keys inherit the permissions of the user who created them

Example request to create an API key:
```http
POST /api/keys
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "description": "My API Key"
}
```

Example response:
```json
{
  "message": "API key created successfully",
  "api_key": {
    "id": 1,
    "key": "probeops.8f7d6e5c4b3a2910...",
    "description": "My API Key",
    "is_active": true,
    "created_at": "2023-01-01T00:00:00Z",
    "last_used_at": null
  }
}
```

## User Roles

The ProbeOps API implements two primary roles:

### User Role (`user`)

- Default role for all registered users
- Access to standard network probe endpoints
- Can manage their own API keys
- Limited by their subscription tier rate limits
- Cannot access admin endpoints

### Admin Role (`admin`)

- Administrative access to all system features
- Can manage all users (create, update, deactivate)
- Can view and manage all API keys
- Can configure rate limits for subscription tiers
- Full access to system status information
- Not subject to rate limits

## Subscription Tiers

Users are assigned one of three subscription tiers that determine their rate limits:

### Free Tier

- Default tier for all new users
- Limited to 100 API requests per day
- Limited to 1,000 API requests per month
- Minimum interval of 15 minutes between probe requests

### Standard Tier

- Paid tier with higher limits
- Limited to 500 API requests per day
- Limited to 5,000 API requests per month
- Minimum interval of 5 minutes between probe requests

### Enterprise Tier

- Premium tier with highest limits
- Limited to 1,000 API requests per day
- Limited to 10,000 API requests per month
- Minimum interval of 5 minutes between probe requests

## Rate Limiting

Rate limiting is applied based on the user's subscription tier. The system tracks:

1. **Daily Limits**: Resets at midnight UTC
2. **Monthly Limits**: Resets on the first day of each month
3. **Interval Limits**: Minimum time between subsequent probe requests

Rate limit headers are included in API responses:

```
X-RateLimit-Limit-Day: 100
X-RateLimit-Remaining-Day: 95
X-RateLimit-Limit-Month: 1000
X-RateLimit-Remaining-Month: 980
X-RateLimit-Reset: 1672531200
```

When a rate limit is exceeded, the API returns a 429 Too Many Requests response.

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Authentication | Description |
|----------|--------|----------------|-------------|
| `/api/auth/register` | POST | None | Register a new user account |
| `/api/auth/login` | POST | None | Login and obtain JWT token |
| `/api/auth/user` | GET | JWT | Get current user information |

### API Key Endpoints

| Endpoint | Method | Authentication | Description |
|----------|--------|----------------|-------------|
| `/api/keys` | GET | JWT | List all API keys for current user |
| `/api/keys` | POST | JWT | Create a new API key |
| `/api/keys/{key_id}` | DELETE | JWT | Delete an API key |

### Network Probe Endpoints

| Endpoint | Method | Authentication | Description |
|----------|--------|----------------|-------------|
| `/api/probes/ping` | POST | JWT/API Key | Run ping on a target |
| `/api/probes/traceroute` | POST | JWT/API Key | Run traceroute on a target |
| `/api/probes/dns` | POST | JWT/API Key | Run DNS lookup on a domain |
| `/api/probes/whois` | POST | JWT/API Key | Run WHOIS lookup on a domain |
| `/api/probes/history` | GET | JWT | Get probe job history |

### Admin Endpoints

| Endpoint | Method | Authentication | Role | Description |
|----------|--------|----------------|------|-------------|
| `/admin/login` | POST | None | N/A | Admin-specific login |
| `/admin/users` | GET | JWT | Admin | List all users |
| `/admin/users/{user_id}` | GET | JWT | Admin | Get user details |
| `/admin/users/{user_id}/role` | POST | JWT | Admin | Update user role |
| `/admin/users/{user_id}/tier` | POST | JWT | Admin | Update subscription tier |
| `/admin/users/{user_id}/status` | POST | JWT | Admin | Toggle user active status |
| `/admin/status` | GET | JWT | Admin | Get system status |
| `/admin/rate-limits` | GET | JWT | Admin | List all rate limit configurations |
| `/admin/rate-limits/{tier}` | GET | JWT | Admin | Get rate limits for specific tier |
| `/admin/rate-limits/{tier}` | PUT | JWT | Admin | Update rate limits for tier |
| `/admin/rate-limits/reset` | POST | JWT | Admin | Reset all rate limits to defaults |

## Frontend Integration Guidelines

### Token Storage

- Store JWT tokens securely using HttpOnly cookies or localStorage (with appropriate security measures)
- Include token refresh mechanism before the 24-hour expiration
- Implement automatic token validation and redirect to login when expired

### Role-Based UI

The frontend should adapt its UI based on the user's role:

#### User Role UI

- Show standard network probe tools
- Display subscription tier information
- Show upgrade options for Free tier users
- Provide API key management interface
- Display rate limit information and usage

#### Admin Role UI

- Include all user role features
- Add an admin dashboard section
- Provide user management interface
- Display system status information
- Include rate limit configuration tools

### Handling Rate Limits

- Display current rate limit status to users
- Show clear error messages when rate limits are reached
- Provide subscription upgrade CTAs for Free tier users who reach limits
- Include countdown timers for interval-based rate limits

## Implementation Examples

### Login Form Component

```javascript
async function handleLogin(username, password) {
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Login failed');
    }
    
    const data = await response.json();
    
    // Store the token
    localStorage.setItem('authToken', data.token);
    
    // Store user info
    const user = data.user;
    
    // Redirect based on role
    if (user.role === 'admin') {
      navigate('/admin/dashboard');
    } else {
      navigate('/dashboard');
    }
    
  } catch (error) {
    // Handle login errors
    showError(error.message);
  }
}
```

### Authenticated API Request Helper

```javascript
async function apiRequest(endpoint, options = {}) {
  // Get the token
  const token = localStorage.getItem('authToken');
  
  // Set default headers
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };
  
  // Add authorization header if token exists
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  // Make the request
  const response = await fetch(endpoint, {
    ...options,
    headers
  });
  
  // Handle unauthorized response
  if (response.status === 401) {
    // Clear token and redirect to login
    localStorage.removeItem('authToken');
    window.location.href = '/login';
    return null;
  }
  
  // Handle rate limit exceeded
  if (response.status === 429) {
    const resetTime = response.headers.get('X-RateLimit-Reset');
    const resetDate = new Date(resetTime * 1000);
    throw new Error(`Rate limit exceeded. Try again after ${resetDate.toLocaleTimeString()}`);
  }
  
  return response;
}
```

### Role-Based Component Rendering

```javascript
function RoleBasedComponent({ children, requiredRole }) {
  const { user } = useAuth();
  
  if (!user) {
    return <LoadingSpinner />;
  }
  
  // For admin role
  if (requiredRole === 'admin' && user.role !== 'admin') {
    return <AccessDenied message="Admin access required" />;
  }
  
  // For specific subscription tiers
  if (['Standard', 'Enterprise'].includes(requiredRole) && !user.subscription_tier.includes(requiredRole)) {
    return <UpgradeRequired currentTier={user.subscription_tier} requiredTier={requiredRole} />;
  }
  
  return children;
}

// Usage
function App() {
  return (
    <Router>
      <Route path="/admin/*">
        <RoleBasedComponent requiredRole="admin">
          <AdminDashboard />
        </RoleBasedComponent>
      </Route>
      <Route path="/premium-features">
        <RoleBasedComponent requiredRole="Standard">
          <PremiumFeatures />
        </RoleBasedComponent>
      </Route>
    </Router>
  );
}
```

### Rate Limit Display Component

```javascript
function RateLimitDisplay() {
  const [limits, setLimits] = useState(null);
  
  useEffect(() => {
    async function fetchLimits() {
      const response = await apiRequest('/api/auth/user');
      if (response?.ok) {
        const data = await response.json();
        
        // Extract rate limit headers
        const dailyLimit = response.headers.get('X-RateLimit-Limit-Day');
        const dailyRemaining = response.headers.get('X-RateLimit-Remaining-Day');
        const monthlyLimit = response.headers.get('X-RateLimit-Limit-Month');
        const monthlyRemaining = response.headers.get('X-RateLimit-Remaining-Month');
        
        setLimits({
          tier: data.user.subscription_tier,
          daily: {
            limit: dailyLimit,
            remaining: dailyRemaining,
            percentage: (dailyRemaining / dailyLimit) * 100
          },
          monthly: {
            limit: monthlyLimit,
            remaining: monthlyRemaining,
            percentage: (monthlyRemaining / monthlyLimit) * 100
          }
        });
      }
    }
    
    fetchLimits();
  }, []);
  
  if (!limits) {
    return <LoadingSpinner />;
  }
  
  return (
    <div className="rate-limit-container">
      <h3>Usage Limits ({limits.tier} Tier)</h3>
      
      <div className="limit-item">
        <span>Daily Usage</span>
        <ProgressBar 
          percentage={limits.daily.percentage} 
          label={`${limits.daily.remaining} / ${limits.daily.limit} remaining`} 
        />
      </div>
      
      <div className="limit-item">
        <span>Monthly Usage</span>
        <ProgressBar 
          percentage={limits.monthly.percentage} 
          label={`${limits.monthly.remaining} / ${limits.monthly.limit} remaining`} 
        />
      </div>
      
      {limits.tier === 'Free' && (
        <div className="upgrade-prompt">
          <p>Need more requests? Upgrade your subscription!</p>
          <Button onClick={() => navigate('/upgrade')}>Upgrade Now</Button>
        </div>
      )}
    </div>
  );
}
```

## Contact Information

For questions or clarification about the RBAC implementation, please contact:

- Backend Team: backend@probeops.com
- Technical Lead: techlead@probeops.com