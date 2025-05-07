"""
Authentication utilities for ProbeOps API
"""
import os
import time
import json
import logging
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import request, jsonify, current_app, g
from werkzeug.local import LocalProxy

from models import User, ApiKey, db

# Configure logging
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "probeops_dev_secret_key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 24 * 60 * 60  # 24 hours in seconds


def get_current_user():
    """Get the current user from the request context"""
    if not hasattr(g, 'current_user'):
        g.current_user = None
        
        # Check for JWT token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                user = verify_jwt_token(token)
                if user:
                    g.current_user = user
            except Exception as e:
                logger.warning(f"JWT validation error: {str(e)}")
        
        # If no valid JWT, check for API key
        if not g.current_user:
            api_key = request.headers.get('X-API-Key')
            if api_key:
                user = verify_api_key(api_key)
                if user:
                    g.current_user = user
            
    return g.current_user


# Create a LocalProxy for easier access
current_user = LocalProxy(get_current_user)


def create_jwt_token(user):
    """Create a new JWT token for the user"""
    payload = {
        "sub": user.id,
        "username": user.username,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token):
    """Verify the JWT token and return the user"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        
        # Check if token is expired
        if "exp" in payload and time.time() > payload["exp"]:
            return None
        
        user = User.query.filter_by(id=user_id, is_active=True).first()
        return user
    except (jwt.PyJWTError, Exception) as e:
        logger.error(f"Error verifying JWT token: {str(e)}")
        return None


def verify_api_key(api_key):
    """Verify the API key and return the user"""
    try:
        key = ApiKey.query.filter_by(key=api_key, is_active=True).first()
        if key:
            # Update last used timestamp
            key.last_used_at = datetime.utcnow()
            db.session.commit()
            
            # Return the associated user
            return key.user if key.user.is_active else None
        return None
    except Exception as e:
        logger.error(f"Error verifying API key: {str(e)}")
        return None


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user:
            return jsonify({
                "error": "Authentication required", 
                "message": "Please provide a valid JWT token or API key."
            }), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user:
            return jsonify({
                "error": "Authentication required", 
                "message": "Please provide a valid JWT token or API key."
            }), 401
        if not current_user.is_admin:
            return jsonify({
                "error": "Forbidden", 
                "message": "Admin privileges required."
            }), 403
        return f(*args, **kwargs)
    return decorated