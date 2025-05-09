# ProbeOps API Frontend Integration Guide

This document provides guidance for frontend developers on how to integrate with the ProbeOps API.

## API Endpoint Structure

The API provides two equivalent URL structures for all endpoints:

1. Direct routes: `/health`, `/users/login`, etc.
2. Prefixed routes: `/api/health`, `/api/users/login`, etc.

Both routes provide the same functionality, but the prefixed routes are recommended for clarity.

## Authentication

The API supports two authentication methods:

### 1. JWT Token Authentication

Used for web applications where a user is logged in through the UI:

```javascript
// Login to get a JWT token
async function login(username, password) {
  const response = await fetch('https://api.probeops.com/api/users/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });
  
  const data = await response.json();
  
  if (response.ok) {
    // Store the token in localStorage or secure cookie
    localStorage.setItem('auth_token', data.token);
    return data;
  } else {
    throw new Error(data.message || 'Login failed');
  }
}

// Use the JWT token for authenticated requests
async function fetchWithAuth(url, options = {}) {
  const token = localStorage.getItem('auth_token');
  
  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`,
  };
  
  return fetch(url, {
    ...options,
    headers,
  });
}

// Example: Get current user info
async function getCurrentUser() {
  const response = await fetchWithAuth('https://api.probeops.com/api/users/me');
  return response.json();
}
```

### 2. API Key Authentication

Used for programmatic access to the API, such as from a backend service or CLI tool:

```javascript
// API key is set in the X-API-Key header
async function fetchWithApiKey(url, options = {}) {
  const API_KEY = 'your_api_key_here';
  
  const headers = {
    ...options.headers,
    'X-API-Key': API_KEY,
  };
  
  return fetch(url, {
    ...options,
    headers,
  });
}

// Example: Get probe history
async function getProbeHistory() {
  const response = await fetchWithApiKey('https://api.probeops.com/api/probes/history');
  return response.json();
}
```

## CORS Configuration

The API has CORS configured to allow requests from the following origins:
- `https://probeops.com`
- `https://www.probeops.com`

If you need to access the API from a different origin during development, contact the API team to add your origin to the CORS allowlist.

## Pagination

Endpoints that return lists of resources (e.g., `/api/probes/history`) support pagination:

```javascript
// Example: Get paginated probe history
async function getProbeHistory(page = 1, per_page = 10, sort_by = 'created_at', sort_order = 'desc') {
  const url = new URL('https://api.probeops.com/api/probes/history');
  url.searchParams.append('page', page);
  url.searchParams.append('per_page', per_page);
  url.searchParams.append('sort_by', sort_by);
  url.searchParams.append('sort_order', sort_order);
  
  const response = await fetchWithAuth(url.toString());
  return response.json();
}
```

The response includes pagination metadata:

```json
{
  "probe_jobs": [...],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 42,
    "pages": 5,
    "next": "/api/probes/history?page=2&per_page=10",
    "prev": null
  }
}
```

## Error Handling

The API returns consistent error responses with HTTP status codes and JSON error messages:

```javascript
async function handleApiRequest(url, options = {}) {
  try {
    const response = await fetchWithAuth(url, options);
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'API request failed');
    }
    
    return response.json();
  } catch (error) {
    console.error('API Error:', error);
    // Handle error appropriately in your UI
    throw error;
  }
}
```

Common error status codes:
- `400 Bad Request`: Invalid input parameters
- `401 Unauthorized`: Authentication required or failed
- `403 Forbidden`: Permission denied
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

## Rate Limiting

The API implements rate limiting to prevent abuse. Rate limits vary by endpoint:

- Authentication endpoints: 5 requests per minute
- Probe endpoints: 30 requests per minute
- Other endpoints: 60 requests per minute

When rate limited, the API will return a `429 Too Many Requests` status code with a `Retry-After` header indicating how many seconds to wait before retrying.

## Mixed Content and Security

When integrating with the API from a secure (HTTPS) frontend:

1. Always use HTTPS URLs to access the API (e.g., `https://api.probeops.com/api/health`)
2. Never mix HTTP and HTTPS content, as browsers will block mixed content

If you encounter mixed content errors:
- Ensure all API URLs in your code use `https://` protocol
- Check for hardcoded URLs in your configuration files
- Verify that all assets (images, scripts, etc.) are loaded over HTTPS

## Example: Complete React Integration

Here's a complete example of integrating with the API using React:

```jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';

// Create an axios instance with default config
const api = axios.create({
  baseURL: 'https://api.probeops.com/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add authentication interceptor
api.interceptors.request.use(config => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Login component
function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  
  const handleLogin = async (e) => {
    e.preventDefault();
    setError(null);
    
    try {
      const response = await api.post('/users/login', { username, password });
      localStorage.setItem('auth_token', response.data.token);
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    }
  };
  
  return (
    <form onSubmit={handleLogin}>
      <h2>Login</h2>
      {error && <div className="error">{error}</div>}
      <div>
        <label>Username:</label>
        <input 
          type="text" 
          value={username} 
          onChange={(e) => setUsername(e.target.value)} 
          required
        />
      </div>
      <div>
        <label>Password:</label>
        <input 
          type="password" 
          value={password} 
          onChange={(e) => setPassword(e.target.value)} 
          required
        />
      </div>
      <button type="submit">Login</button>
    </form>
  );
}

// Probe history component
function ProbeHistory() {
  const [probes, setProbes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({});
  
  useEffect(() => {
    const fetchProbes = async () => {
      try {
        setLoading(true);
        const response = await api.get('/probes/history', {
          params: { page, per_page: 10, sort_by: 'created_at', sort_order: 'desc' }
        });
        
        setProbes(response.data.probe_jobs);
        setPagination(response.data.pagination);
        setError(null);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch probe history');
      } finally {
        setLoading(false);
      }
    };
    
    fetchProbes();
  }, [page]);
  
  const handleNextPage = () => {
    if (pagination.next) {
      setPage(page + 1);
    }
  };
  
  const handlePrevPage = () => {
    if (pagination.prev) {
      setPage(page - 1);
    }
  };
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div className="error">{error}</div>;
  
  return (
    <div>
      <h2>Probe History</h2>
      
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Target</th>
            <th>Status</th>
            <th>Created At</th>
          </tr>
        </thead>
        <tbody>
          {probes.map(probe => (
            <tr key={probe.id}>
              <td>{probe.id}</td>
              <td>{probe.probe_type}</td>
              <td>{probe.target}</td>
              <td>{probe.success ? 'Success' : 'Failed'}</td>
              <td>{new Date(probe.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      
      <div className="pagination">
        <button onClick={handlePrevPage} disabled={!pagination.prev}>
          Previous
        </button>
        <span>Page {pagination.page} of {pagination.pages}</span>
        <button onClick={handleNextPage} disabled={!pagination.next}>
          Next
        </button>
      </div>
    </div>
  );
}

// Example of running a ping probe
function PingProbe() {
  const [target, setTarget] = useState('');
  const [count, setCount] = useState(4);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      setLoading(true);
      setError(null);
      setResult(null);
      
      const response = await api.post('/probes/ping', { 
        host: target,
        count: parseInt(count)
      });
      
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Ping probe failed');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div>
      <h2>Ping Probe</h2>
      
      <form onSubmit={handleSubmit}>
        <div>
          <label>Target Host:</label>
          <input 
            type="text" 
            value={target} 
            onChange={(e) => setTarget(e.target.value)} 
            required
            placeholder="example.com or 192.168.1.1"
          />
        </div>
        <div>
          <label>Ping Count:</label>
          <input 
            type="number" 
            min="1" 
            max="10" 
            value={count} 
            onChange={(e) => setCount(e.target.value)} 
          />
        </div>
        <button type="submit" disabled={loading}>
          {loading ? 'Running...' : 'Run Ping'}
        </button>
      </form>
      
      {error && <div className="error">{error}</div>}
      
      {result && (
        <div className="result">
          <h3>Result</h3>
          <pre>{result.result}</pre>
        </div>
      )}
    </div>
  );
}
```

## API Key Management

To create and manage API keys, use the API key management endpoints:

```javascript
// Create a new API key
async function createApiKey(description) {
  const response = await fetchWithAuth('https://api.probeops.com/api/apikeys', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ description }),
  });
  
  return response.json();
}

// List all API keys
async function listApiKeys() {
  const response = await fetchWithAuth('https://api.probeops.com/api/apikeys');
  return response.json();
}

// Delete an API key
async function deleteApiKey(keyId) {
  const response = await fetchWithAuth(`https://api.probeops.com/api/apikeys/${keyId}`, {
    method: 'DELETE',
  });
  
  return response.status === 204; // No content response indicates success
}
```

## Need Help?

If you have questions or need assistance integrating with the ProbeOps API, contact the API team at api@probeops.com or create an issue in the GitHub repository.