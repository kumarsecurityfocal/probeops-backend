# ProbeOps API: Frontend Integration Guide

This guide provides frontend developers with the information needed to successfully integrate with the ProbeOps API.

## Table of Contents

1. [API Basics](#api-basics)
2. [Authentication](#authentication)
3. [Available Documentation](#available-documentation)
4. [Common Integration Patterns](#common-integration-patterns)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Best Practices](#best-practices)

## API Basics

ProbeOps API is a RESTful service that provides network diagnostic tools including ping, traceroute, DNS lookup, and WHOIS lookup capabilities.

- **Base URL**: `/api`
- **Content Type**: All requests and responses use JSON
- **Authentication**: JWT tokens or API Keys

## Authentication

The API supports two authentication methods:

### JWT Token Authentication

For interactive user sessions:

1. **Login to obtain a token**:
   ```javascript
   async function login(username, password) {
     const response = await fetch('/api/users/login', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ username, password })
     });
     
     const data = await response.json();
     if (response.ok) {
       // Store the token securely
       localStorage.setItem('authToken', data.token);
       return data.user;
     } else {
       throw new Error(data.message || 'Login failed');
     }
   }
   ```

2. **Include the token in requests**:
   ```javascript
   function getAuthHeaders() {
     const token = localStorage.getItem('authToken');
     return token ? { 'Authorization': `Bearer ${token}` } : {};
   }
   
   async function fetchUserProfile() {
     const response = await fetch('/api/users/me', {
       headers: {
         ...getAuthHeaders(),
         'Content-Type': 'application/json'
       }
     });
     
     return response.json();
   }
   ```

### API Key Authentication

For machine-to-machine or automated access:

1. **Create an API key** (requires JWT authentication first):
   ```javascript
   async function createApiKey(description) {
     const response = await fetch('/api/apikeys', {
       method: 'POST',
       headers: {
         ...getAuthHeaders(),
         'Content-Type': 'application/json'
       },
       body: JSON.stringify({ description })
     });
     
     return response.json();
   }
   ```

2. **Use the API key in requests**:
   ```javascript
   async function pingWithApiKey(apiKey, host) {
     const response = await fetch('/api/probes/ping', {
       method: 'POST',
       headers: {
         'X-API-Key': apiKey,
         'Content-Type': 'application/json'
       },
       body: JSON.stringify({ host, count: 4 })
     });
     
     return response.json();
   }
   ```

## Available Documentation

Complete API documentation is available in the following locations:

1. **API Endpoints Reference**: `/docs/API_ENDPOINTS_REFERENCE.md`
   - Comprehensive listing of all endpoints
   - Request/response formats
   - Authentication requirements

2. **RBAC Documentation**: `/docs/RBAC_DOCUMENTATION.md`
   - Role-Based Access Control details
   - User roles and permissions
   - Subscription tiers
   - Rate limiting

3. **API Examples**: `/docs/API_EXAMPLES.md`
   - Example requests with curl
   - Sample response data
   - Common use cases

## Common Integration Patterns

### Role-Based UI Components

Use the user's role to conditionally render UI components:

```jsx
function AdminOnlySection({ children }) {
  const { user } = useAuth();
  
  if (!user || user.role !== 'admin') {
    return null;
  }
  
  return <div className="admin-section">{children}</div>;
}

// Usage
function Dashboard() {
  return (
    <div>
      <RegularUserTools />
      <AdminOnlySection>
        <UserManagement />
        <SystemStatus />
      </AdminOnlySection>
    </div>
  );
}
```

### Tier-Based Feature Access

Restrict access to features based on subscription tier:

```jsx
function TierRestrictedFeature({ requiredTier, children }) {
  const { user } = useAuth();
  const tierLevels = { 'Free': 0, 'Standard': 1, 'Enterprise': 2 };
  
  if (!user) return <LoadingSpinner />;
  
  const userTierLevel = tierLevels[user.subscription_tier] || 0;
  const requiredTierLevel = tierLevels[requiredTier] || 0;
  
  if (userTierLevel < requiredTierLevel) {
    return (
      <div className="upgrade-prompt">
        <p>This feature requires a {requiredTier} subscription.</p>
        <button onClick={() => navigate('/upgrade')}>Upgrade Now</button>
      </div>
    );
  }
  
  return children;
}

// Usage
function ProbeDashboard() {
  return (
    <div>
      <BasicProbes />
      <TierRestrictedFeature requiredTier="Standard">
        <AdvancedProbes />
      </TierRestrictedFeature>
    </div>
  );
}
```

### Rate Limit Display

Show the user's current rate limit status:

```jsx
function RateLimitDisplay() {
  const [limits, setLimits] = useState(null);
  
  useEffect(() => {
    async function fetchLimits() {
      const response = await fetch('/api/users/me', {
        headers: getAuthHeaders()
      });
      
      if (response.ok) {
        const dailyLimit = response.headers.get('X-RateLimit-Limit-Day');
        const dailyRemaining = response.headers.get('X-RateLimit-Remaining-Day');
        
        setLimits({
          daily: {
            limit: parseInt(dailyLimit, 10),
            remaining: parseInt(dailyRemaining, 10),
            percentUsed: ((parseInt(dailyLimit, 10) - parseInt(dailyRemaining, 10)) / parseInt(dailyLimit, 10)) * 100
          }
        });
      }
    }
    
    fetchLimits();
  }, []);
  
  if (!limits) return <LoadingSpinner />;
  
  return (
    <div className="rate-limit-info">
      <h4>Daily API Usage</h4>
      <div className="progress-bar">
        <div 
          className="progress-fill" 
          style={{ width: `${limits.daily.percentUsed}%` }}
        ></div>
      </div>
      <p>{limits.daily.remaining} of {limits.daily.limit} requests remaining</p>
    </div>
  );
}
```

## Error Handling

Implement consistent error handling for API responses:

```javascript
async function apiRequest(endpoint, options = {}) {
  try {
    const headers = {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
      ...options.headers
    };
    
    const response = await fetch(endpoint, { ...options, headers });
    
    // Handle different response status codes
    if (response.status === 401) {
      // Unauthorized - redirect to login
      localStorage.removeItem('authToken');
      window.location.href = '/login';
      return null;
    }
    
    if (response.status === 403) {
      // Forbidden - insufficient permissions
      const errorData = await response.json();
      showErrorNotification(`Access denied: ${errorData.message}`);
      return null;
    }
    
    if (response.status === 429) {
      // Rate limit exceeded
      const resetTime = response.headers.get('X-RateLimit-Reset');
      const resetDate = new Date(parseInt(resetTime, 10) * 1000);
      showErrorNotification(`Rate limit exceeded. Try again after ${resetDate.toLocaleTimeString()}`);
      return null;
    }
    
    if (!response.ok) {
      // Other errors
      const errorData = await response.json();
      throw new Error(errorData.message || 'API request failed');
    }
    
    return response.json();
  } catch (error) {
    showErrorNotification(error.message);
    return null;
  }
}
```

## Rate Limiting

Handle rate limiting gracefully in your application:

```javascript
function ProbeButton({ probeType, probeFunction }) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rateLimit, setRateLimit] = useState(null);
  
  async function runProbe() {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`/api/probes/${probeType}`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ /* probe parameters */ })
      });
      
      // Check for rate limit headers
      const dailyRemaining = response.headers.get('X-RateLimit-Remaining-Day');
      const resetTime = response.headers.get('X-RateLimit-Reset');
      
      setRateLimit({
        remaining: parseInt(dailyRemaining, 10),
        resetTime: new Date(parseInt(resetTime, 10) * 1000)
      });
      
      if (response.status === 429) {
        setError(`Rate limit exceeded. Try again after ${rateLimit.resetTime.toLocaleTimeString()}`);
        return;
      }
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Probe failed');
      }
      
      const data = await response.json();
      probeFunction(data);
      
    } catch (error) {
      setError(error.message);
    } finally {
      setIsLoading(false);
    }
  }
  
  return (
    <div>
      <button 
        onClick={runProbe} 
        disabled={isLoading || (rateLimit && rateLimit.remaining === 0)}
      >
        {isLoading ? 'Running...' : `Run ${probeType}`}
      </button>
      
      {error && <div className="error-message">{error}</div>}
      
      {rateLimit && rateLimit.remaining === 0 && (
        <div className="rate-limit-warning">
          Rate limit reached. Try again after {rateLimit.resetTime.toLocaleTimeString()}
        </div>
      )}
    </div>
  );
}
```

## Best Practices

1. **Token Management**
   - Store JWT tokens securely (HttpOnly cookies where possible, or localStorage)
   - Implement token refresh before expiration
   - Clear tokens on logout or when unauthorized responses are received

2. **Error Handling**
   - Implement global error handling for API requests
   - Show clear user-friendly error messages
   - Log errors for troubleshooting

3. **Role-Based UI**
   - Hide or disable UI elements based on user role
   - Provide clear feedback when permissions are insufficient
   - Direct users to upgrade their subscription when appropriate

4. **Rate Limit Awareness**
   - Show users their current usage and limits
   - Implement cooldown periods for rate-limited operations
   - Disable UI elements when rate limits are reached

5. **Progressive Enhancement**
   - Start with basic functionality for Free tier users
   - Enhance the UI for higher subscription tiers
   - Clearly indicate premium features

6. **Accessibility**
   - Ensure error messages are accessible
   - Provide alternative text for visual indicators of rate limits or permissions
   - Maintain keyboard navigability for all permission levels

## Contact

If you have any questions about integrating with the ProbeOps API, please contact:

- Frontend Team: frontend@probeops.com
- API Support: api-support@probeops.com