# Using the ProbeOps API Postman Collection

This guide explains how to use the Postman collection to test the ProbeOps API.

## Prerequisites

1. [Postman](https://www.postman.com/downloads/) installed on your computer
2. The ProbeOps API running on a server

## Setup

1. **Import the Collection**
   - Open Postman
   - Click "Import" in the top left
   - Select the `probeops_api_postman_collection.json` file
   - The "ProbeOps API" collection will appear in your collections list

2. **Create an Environment**
   - Click the gear icon in the top right
   - Click "Add" to create a new environment
   - Name it "ProbeOps API"
   - Add the following variables:
     - `base_url`: The URL where your API is running (e.g., `http://localhost:5000` or `https://api.probeops.com`)
     - `auth_token`: Leave this blank initially (it will be populated automatically)
     - `api_key`: Leave this blank initially (it will be populated automatically)
     - `api_key_id`: Leave this blank initially (it will be populated automatically)
   - Click "Save"
   - Select your new environment from the dropdown in the top right

## Authentication

The collection includes automatic scripts that save authentication tokens and API keys to your environment variables. Follow these steps to authenticate:

1. **Login to Get JWT Token**
   - Open the "Authentication" folder
   - Select the "Login" request
   - Modify the request body with the admin credentials:
     ```json
     {
         "email": "admin@probeops.com",
         "password": "testpass123"
     }
     ```
   - Click "Send"
   - If successful, the response will include a JWT token, and it will be automatically saved to the `auth_token` environment variable

2. **Create an API Key**
   - Open the "API Keys" folder
   - Select the "Create API Key" request
   - Add a description in the request body:
     ```json
     {
         "description": "Postman Testing Key"
     }
     ```
   - Click "Send"
   - If successful, the API key will be automatically saved to the `api_key` environment variable, and its ID will be saved to `api_key_id`

## Testing API Endpoints

### Network Probes

The collection includes two folders for testing network probes:

1. **Network Probes (JWT Auth)**: Uses JWT token authentication
2. **Network Probes (API Key Auth)**: Uses API key authentication

Both folders contain the same set of probe endpoints:

- **Ping Probe**: Test connectivity to a host
- **Traceroute Probe**: Trace the network path to a host
- **DNS Lookup**: Look up DNS records for a domain
- **WHOIS Lookup**: Look up WHOIS information for a domain

To use these endpoints:

1. Select the desired probe request
2. Modify the request body as needed (host, domain, parameters)
3. Click "Send"
4. View the probe results in the response

### Probe History

To view the history of probe operations:

1. Open the "Network Probes (JWT Auth)" folder
2. Select the "Probe History" request
3. Click "Send"
4. View the list of probe jobs in the response

### Admin Operations

The "Admin" folder contains endpoints for administrative operations that require admin privileges:

- **List All Users**: Get a list of all users in the system
- **Get User Details**: Get details for a specific user
- **Update User Role**: Change a user's role (user/admin)
- **Update User Subscription Tier**: Change a user's subscription tier
- **Toggle User Active Status**: Activate/deactivate a user
- **Server Status**: Get system status information

To use these endpoints:

1. Select the desired admin request
2. Modify the request parameters or body as needed
3. Click "Send"
4. View the results in the response

## Rate Limiting

The API includes rate limiting based on subscription tiers. After sending requests, check the response headers for rate limit information:

- `X-RateLimit-Limit-Day`: Daily request limit
- `X-RateLimit-Remaining-Day`: Remaining requests for the day
- `X-RateLimit-Limit-Month`: Monthly request limit
- `X-RateLimit-Remaining-Month`: Remaining requests for the month
- `X-RateLimit-Reset`: Timestamp when the rate limit will reset

If you exceed the rate limit, the API will return a 429 Too Many Requests response.

## Troubleshooting

### Authentication Issues

If you encounter 401 Unauthorized errors:

1. Your JWT token may have expired. Try logging in again to refresh the token.
2. Your API key may be invalid or deactivated. Create a new API key.

### Missing Environment Variables

If requests fail because environment variables are missing:

1. Make sure you've selected the correct environment
2. Run the Login request to populate the `auth_token` variable
3. Run the Create API Key request to populate the `api_key` and `api_key_id` variables

### General Issues

If you're experiencing other problems:

1. Check that the API server is running
2. Verify that the `base_url` environment variable is set correctly
3. Check the API server logs for error messages
4. Try the Health Check request to verify basic API connectivity