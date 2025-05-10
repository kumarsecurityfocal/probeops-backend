"""
Authentication services for ProbeOps API
"""
import os
import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import request, jsonify, g, current_app

from probeops.models import User, ApiKey
from probeops.app import db

# Configure logging
logger = logging.getLogger(__name__)

# JWT configuration
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-secret-key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24  # Token expires after 24 hours


def get_current_user():
    """Get the current user from the request context"""
    if hasattr(g, 'current_user'):
        return g.current_user
    
    # Check for JWT token
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        user = verify_jwt_token(token)
        if user:
            g.current_user = user
            return user
    
    # Check for API key
    api_key = request.headers.get('X-API-Key')
    if api_key:
        user = verify_api_key(api_key)
        if user:
            g.current_user = user
            return user
    
    return None


def create_jwt_token(user):
    """Create a new JWT token for the user"""
    now = datetime.utcnow()
    payload = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'subscription_tier': user.subscription_tier,
        'iat': now,
        'exp': now + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token):
    """Verify the JWT token and return the user"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Check if token is expired
        exp = payload.get('exp')
        if not exp or datetime.utcnow() > datetime.fromtimestamp(exp):
            logger.warning("Token expired")
            return None
        
        # Get user
        user_id = payload.get('user_id')
        if not user_id:
            logger.warning("Token missing user_id")
            return None
        
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"User {user_id} not found")
            return None
        
        if not user.is_active:
            logger.warning(f"User {user_id} is inactive")
            return None
        
        return user
    
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None


def verify_api_key(api_key):
    """Verify the API key and return the user"""
    try:
        # Find API key in the database
        api_key_obj = ApiKey.query.filter_by(key=api_key, is_active=True).first()
        if not api_key_obj:
            logger.warning(f"API key not found or inactive")
            return None
        
        # Get user
        user = api_key_obj.user
        if not user:
            logger.warning(f"User for API key not found")
            return None
        
        if not user.is_active:
            logger.warning(f"User for API key is inactive")
            return None
        
        # Update last used timestamp
        api_key_obj.last_used_at = datetime.utcnow()
        db.session.commit()
        
        return user
    
    except Exception as e:
        logger.error(f"Error verifying API key: {e}")
        return None


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        
        if not user.is_admin_user():
            return jsonify({"error": "Admin privileges required"}), 403
        
        return f(*args, **kwargs)
    return decorated


def role_required(role):
    """Decorator to require a specific role"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            
            if user.role != role and not user.is_admin_user():
                return jsonify({"error": f"{role.capitalize()} role required"}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def tier_required(tier):
    """Decorator to require a specific subscription tier or higher"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            
            if not user.has_tier(tier) and not user.is_admin_user():
                return jsonify({"error": f"{tier} tier required"}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator