"""
API Blueprint for ProbeOps API
This module defines a Flask Blueprint for the /api prefix
"""
from flask import Blueprint, jsonify, request, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging

# Setup logger
logger = logging.getLogger(__name__)

# Create the Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Define health check endpoint
@api_bp.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ProbeOps API",
        "version": "1.0.0"
    })

# Mirror of root endpoint
@api_bp.route('/')
def root():
    """API root endpoint"""
    return jsonify({
        "name": "ProbeOps API",
        "description": "Network diagnostics and monitoring API",
        "version": "1.0.0",
        "endpoints": {
            "/api/health": "Health check endpoint",
            "/api/probes/ping": "Ping a host",
            "/api/probes/traceroute": "Run traceroute to a host",
            "/api/probes/dns": "Perform DNS lookup",
            "/api/probes/whois": "Run WHOIS lookup",
            "/api/probes/history": "View probe history",
            "/api/users/register": "Register a new user",
            "/api/users/login": "Login and get JWT token",
            "/api/users/me": "Get current user info",
            "/api/apikeys": "Manage API keys"
        },
        "documentation": "https://docs.probeops.com/api"
    })