# Frontend Integration Guide

## Current Issue: Mixed Content Error

The frontend is making insecure HTTP requests to a hardcoded IP address:
```
Mixed Content: The page at 'https://probeops.com/auth' was loaded over HTTPS, but requested an insecure XMLHttpRequest endpoint 'http://35.173.110.195:5000/users/login'.
```

## Solution Steps

### 1. Update Frontend API URLs

Replace any hardcoded backend URLs in the frontend code:

```javascript
// Change this:
const API_BASE_URL = 'http://35.173.110.195:5000';

// To this:
const API_BASE_URL = '/api'; // Use relative URL for same-domain deployment
```

### 2. Configure Frontend Proxy for Development

If using a modern frontend framework (React, Vue, Angular), configure the development proxy:

**React (package.json)**:
```json
"proxy": "http://localhost:5000"
```

**Vue (vue.config.js)**:
```javascript
module.exports = {
  devServer: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
}
```

### 3. Configure Production NGINX Proxy

Add this to your NGINX configuration:

```nginx
server {
    listen 443 ssl;
    server_name probeops.com www.probeops.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Frontend static files
    location / {
        root /var/www/probeops/frontend;
        try_files $uri $uri/ /index.html;
    }

    # API proxy to backend
    location /api/ {
        proxy_pass http://probeops-api:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### 4. Check for Hardcoded URLs in Frontend Config

Search for hardcoded URLs in:
- Environment files (`.env`, `.env.production`)
- Configuration files
- API service modules
- Fetch/Axios calls within components

Common files to check:
```
src/config/api.js
src/services/api.js
src/utils/http.js
src/store/actions.js
```

### 5. Use Environment Variables

For flexible deployment, use environment variables instead of hardcoded URLs:

```javascript
// In your API client
const API_URL = process.env.REACT_APP_API_URL || '/api';

// Then at build time or runtime, set the environment variable if needed
// REACT_APP_API_URL=/api
```

### Testing After Changes

1. Deploy the updated frontend with these changes
2. Open browser developer tools (F12)
3. Go to the Network tab
4. Verify requests are going to `/api/users/login` (relative URL) instead of hardcoded IP
5. Check that requests use HTTPS protocol

## Server Architecture

With these changes, the architecture will be:

1. Frontend and backend will be decoupled services
2. NGINX will route requests appropriately:
   - Frontend requests -> static files
   - `/api/*` requests -> backend service
3. Backend service runs in Docker with internal network only (no public ports)
4. All external communication uses HTTPS