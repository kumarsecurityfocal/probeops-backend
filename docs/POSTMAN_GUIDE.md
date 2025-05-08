# ProbeOps API Postman Collection Guide

This guide explains how to use the provided Postman collection to test the ProbeOps API.

## Importing the Collection

1. Open Postman
2. Click on "Import" in the top left
3. Upload the `probeops_api_postman_collection.json` file
4. The collection will be imported with all requests and variables

## Setting Variables

The collection uses variables to make testing easier:

- `baseUrl`: Set this to your API server URL (default: http://localhost:5000)
- `token`: This will be automatically set when you login
- `apiKey`: This will be automatically set when you register or create an API key

To manually set or update these variables:
1. Click on the collection name "ProbeOps API"
2. Go to the "Variables" tab
3. Update the "Current Value" field for the variable you want to change
4. Click "Save"

## Testing Flow

Here's a recommended testing flow:

### 1. Basic Health Checks
- Run "Health Check" to verify the API is accessible
- Run "API Info" to see available endpoints

### 2. User Registration and Login
- Run "Register User" with your desired username/password
  - This automatically saves your API key to the collection variable
- Run "Login User" with the same credentials
  - This automatically saves your JWT token to the collection variable

### 3. Test Protected Endpoints
Now you can test any of the protected endpoints:
- "Get Current User" to verify your JWT token works
- Any of the network probes using either JWT or API key authentication

### 4. API Key Management
- "List API Keys" to see your existing API keys
- "Create API Key" to create additional keys
- "Delete API Key" to remove keys you no longer need

### 5. Running Network Probes
You can run network diagnostics using either JWT or API key authentication:
- Use the "Network Probes (JWT)" folder if you're authenticated with a JWT token
- Use the "Network Probes (API Key)" folder if you're using an API key

## Request Details

### Authentication

The collection includes two authentication methods:

1. **JWT Token Authentication**:
   - Set via the "Authorization" header: `Bearer {{token}}`
   - Obtained through the "Login User" request
   - Used in most requests

2. **API Key Authentication**:
   - Set via the "X-API-Key" header: `{{apiKey}}`
   - Obtained through "Register User" or "Create API Key" requests
   - Used primarily for probe operations

### Network Probes

For each network probe, you can customize parameters in the request body:

- **Ping**:
  - `host`: The target hostname or IP address
  - `count`: Number of ping packets to send (default: 4)

- **Traceroute**:
  - `host`: The target hostname or IP address
  - `max_hops`: Maximum number of hops (default: 30)

- **DNS Lookup**:
  - `domain`: The domain to lookup
  - `record_type`: DNS record type (A, AAAA, MX, TXT, etc.)

- **WHOIS Lookup**:
  - `domain`: The domain to query

### Probe History

You can filter and paginate probe history:
- `page`: Page number (starting from 1)
- `per_page`: Number of items per page
- `probe_type`: Filter by probe type (ping, traceroute, dns, whois)

## Troubleshooting

### Authentication Issues
- If you get 401 Unauthorized errors, your token or API key might be invalid or expired
- Try running the "Login User" request again to get a fresh token
- Check that your token and API key variables are properly set

### Request Failures
- Check the URL in the request matches your API server
- Verify your baseUrl variable is set correctly
- Check the API server logs for more detailed error information

### Rate Limiting
- If you get 429 Too Many Requests errors, you've hit a rate limit
- Wait a minute and try again, or adjust the rate limits in your server configuration