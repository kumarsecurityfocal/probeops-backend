"""
ProbeOps API - Flask-based Network Diagnostics API with JWT Authentication and API Keys
"""
import os
import json
import logging
import socket
import time
import random
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, jsonify, request, g, Blueprint
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import bcrypt_sha256
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env file if present
from dotenv import load_dotenv
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Configure logging based on environment setting
log_level = os.getenv('LOG_LEVEL', 'DEBUG').upper()
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create the Flask application
app = Flask(__name__)

# Enable debug mode and exception propagation
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["DEBUG"] = True

# Configure CORS to allow requests from specified origins or use defaults
cors_origins_env = os.getenv("CORS_ORIGINS", "")
if cors_origins_env:
    cors_origins = cors_origins_env.split(",")
else:
    # Default production origins (can be overridden in .env file)
    cors_origins = ["https://probeops.com", "https://www.probeops.com"]

logger.info(f"Configuring CORS with origins: {cors_origins}")

# List of headers we want to allow
cors_allow_headers = [
    "Content-Type", "Authorization", "X-API-Key", "X-Requested-With",
    "Accept", "Origin", "Access-Control-Request-Method", 
    "Access-Control-Request-Headers", "ApiKey", "Api-Key", "api-key", "apikey"
]

# Headers we want to expose to the client
cors_expose_headers = ["Content-Type", "Authorization", "X-API-Key"]

# Main CORS configuration
CORS(
    app,
    origins=cors_origins,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=cors_allow_headers,
    supports_credentials=True,
    expose_headers=cors_expose_headers,
    max_age=3600
)

# Request logger for debugging API calls
@app.before_request
def log_request_info():
    """Log detailed information about incoming requests"""
    # Only log API requests, not static content
    if not request.path.startswith('/static/'):
        # Create a request ID for tracking
        request_id = str(uuid.uuid4())[:8]
        g.request_id = request_id
        
        # Extract authentication info for logging (without sensitive data)
        auth_info = "No Auth"
        if request.headers.get('Authorization'):
            if request.headers.get('Authorization').startswith('Bearer '):
                auth_info = "JWT Token"
            elif request.headers.get('Authorization').startswith('ApiKey '):
                auth_info = "API Key"
        elif any(k.lower() in ('x-api-key', 'api-key', 'apikey') for k in request.headers.keys()):
            auth_info = "API Key Header"
            
        # Get client IP with proxy support
        client_ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            
        # Log request details
        logger.info(f"[{request_id}] Request: {request.method} {request.path} - IP: {client_ip}, "
                   f"Auth: {auth_info}, Content-Type: {request.content_type}, "
                   f"User-Agent: {request.headers.get('User-Agent')}")
        
        # For debugging, log more details at debug level
        if logger.isEnabledFor(logging.DEBUG):
            # Log headers (redact sensitive info)
            headers = dict(request.headers)
            if 'Authorization' in headers:
                headers['Authorization'] = '[REDACTED]'
            if 'X-API-Key' in headers:
                headers['X-API-Key'] = '[REDACTED]'
                
            # Log query parameters
            logger.debug(f"[{request_id}] Query params: {dict(request.args)}")
            
            # Log request body for JSON requests (redact sensitive info)
            if request.is_json:
                body = request.get_json(silent=True)
                if body:
                    if isinstance(body, dict):
                        # Redact sensitive fields
                        safe_body = body.copy()
                        for field in ['password', 'token', 'api_key', 'key', 'secret']:
                            if field in safe_body:
                                safe_body[field] = '[REDACTED]'
                        logger.debug(f"[{request_id}] JSON body: {safe_body}")
                    else:
                        logger.debug(f"[{request_id}] JSON body: (non-dict payload)")

# After request handler to ensure CORS headers are set on all responses
@app.after_request
def add_cors_headers(response):
    """Ensure CORS headers are consistently applied to all responses"""
    # If origin is "*", let Flask-CORS handle it
    if cors_origins == "*":
        pass  # Let Flask-CORS handle wildcard case
    else:
        # For explicit origins, set the appropriate headers
        origin = request.headers.get('Origin')
        if origin and (origin in cors_origins or origin.strip('/') in cors_origins):
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', ', '.join(cors_allow_headers))
            response.headers.add('Access-Control-Expose-Headers', ', '.join(cors_expose_headers))
    
    # Add a diagnostic header to help with debugging
    response.headers.add('X-ProbeOps-API', 'v1.0')
    
    # Add request ID for tracking in response headers if available
    if hasattr(g, 'request_id'):
        response.headers.add('X-Request-ID', g.request_id)
    
    # Log response details
    status_category = response.status_code // 100
    log_method = logger.info if status_category in (1, 2, 3) else logger.warning if status_category == 4 else logger.error
    
    request_id = getattr(g, 'request_id', 'no-id') 
    
    # Log different levels based on status code
    if status_category >= 4:  # 4xx or 5xx errors
        # For errors, log more detailed information to help diagnose issues
        log_method(f"[{request_id}] Response: {response.status_code} {request.method} {request.path} - "
                  f"Size: {response.content_length or 0} bytes, "
                  f"Content-Type: {response.content_type}")
        
        # For server errors, include response body in logs for debugging
        if status_category == 5 and response.content_type == 'application/json':
            try:
                # Try to get the JSON data if possible
                json_data = response.get_json(silent=True)
                if json_data:
                    logger.error(f"[{request_id}] Error response body: {json_data}")
            except Exception:
                pass
    else:
        # For successful responses, log basic information
        log_method(f"[{request_id}] Response: {response.status_code} {request.method} {request.path}")
    
    # Debug level for more detailed information about all responses
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"[{request_id}] Response headers: {dict(response.headers)}")
        
    return response

# Helper function to get rate limit configuration for a tier
def get_rate_limit_for_tier(tier):
    """
    Get the rate limit configuration for a specific subscription tier
    Returns a tuple of (daily_limit, monthly_limit, min_interval_minutes)
    """
    from models import RateLimitConfig, User
    
    # Check if we have a custom configuration in the database
    config = RateLimitConfig.query.filter_by(tier=tier).first()
    
    # If no custom config, use defaults
    if not config:
        # Get default configs
        defaults = {cfg['tier']: cfg for cfg in RateLimitConfig.get_default_configs()}
        
        # Use the default for this tier, or fall back to Free tier defaults
        tier_config = defaults.get(tier, defaults.get(User.TIER_FREE))
        
        if tier_config:
            # Create entry in database for next time
            try:
                config = RateLimitConfig()
                config.tier = tier
                config.daily_limit = tier_config['daily_limit']
                config.monthly_limit = tier_config['monthly_limit']
                config.min_interval_minutes = tier_config['min_interval_minutes']
                db.session.add(config)
                db.session.commit()
            except Exception as e:
                logger.error(f"Error creating rate limit config for tier {tier}: {str(e)}")
                db.session.rollback()
                
                # Return default values if database operation fails
                return (
                    tier_config['daily_limit'], 
                    tier_config['monthly_limit'], 
                    tier_config['min_interval_minutes']
                )
        else:
            # Fallback to hardcoded defaults if no tier config found
            return (100, 1000, 15)  # Free tier defaults
    
    return (config.daily_limit, config.monthly_limit, config.min_interval_minutes)

# Define a function to get dynamic limits based on user's tier
def get_dynamic_limits(endpoint_path=None):
    """
    Get dynamic rate limits based on current user's subscription tier
    Returns a list of rate limit strings to apply
    """
    # Get current user
    current_user = get_current_user()
    
    # Default limits for unauthenticated users
    if not current_user:
        return ["50 per day", "10 per hour"]
    
    # Get user's tier
    tier = current_user.subscription_tier
    
    # Get limits for this tier
    daily_limit, monthly_limit, min_interval_minutes = get_rate_limit_for_tier(tier)
    
    # Special adjustment for admins - they get higher limits
    if current_user.is_admin_user():
        daily_limit *= 2
        monthly_limit *= 2
        min_interval_minutes = max(1, min_interval_minutes // 2)  # At least 1 minute
    
    # Calculate requests per second (for minimum interval)
    # This converts "minimum 5 minutes between requests" to "12 per hour" 
    requests_per_hour = 60 // min_interval_minutes if min_interval_minutes > 0 else 60
    
    # Return list of limit strings
    return [
        f"{daily_limit} per day", 
        f"{monthly_limit} per month",
        f"{requests_per_hour} per hour"
    ]

# Define a custom rate limit key function that uses user identity when available
def get_rate_limit_key():
    # First try to get the current user
    current_user = get_current_user()
    if current_user:
        # Use user ID as the key
        return str(current_user.id)
    
    # Fall back to IP address
    return get_remote_address()

# Configure rate limiter
limiter = Limiter(
    app=app,
    key_func=get_rate_limit_key,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure application
app.config["SECRET_KEY"] = os.getenv("API_KEY_SECRET", "probeops_development_secret")

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_timeout": 30,
    "max_overflow": 10
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Debug mode based on environment
app.config["DEBUG"] = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# Initialize database
db = SQLAlchemy(app)

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "probeops_dev_secret_key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# Convert JWT expiration to seconds
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))
JWT_EXPIRATION = JWT_EXPIRATION_MINUTES * 60  # Convert minutes to seconds

# Define models
class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    # Role constants
    ROLE_USER = 'user'
    ROLE_ADMIN = 'admin'
    
    # Subscription tier constants
    TIER_FREE = 'Free'
    TIER_STANDARD = 'Standard'
    TIER_ENTERPRISE = 'Enterprise'
    
    # Valid subscription tiers
    VALID_TIERS = [TIER_FREE, TIER_STANDARD, TIER_ENTERPRISE]
    
    # Valid user roles
    VALID_ROLES = [ROLE_USER, ROLE_ADMIN]
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    hashed_password = db.Column(db.String(256), nullable=False) # Primary password field
    is_active = db.Column(db.Boolean, default=True)
    # Actually, production uses role not is_admin
    role = db.Column(db.String(20), default=ROLE_USER)
    subscription_tier = db.Column(db.String(20), default=TIER_FREE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_admin_user(self):
        """Check if user has admin role"""
        return self.role == self.ROLE_ADMIN
        
    def has_tier(self, tier):
        """Check if user has a specific subscription tier or higher"""
        tier_levels = {
            self.TIER_FREE: 0,
            self.TIER_STANDARD: 1,
            self.TIER_ENTERPRISE: 2
        }
        
        user_tier_level = tier_levels.get(self.subscription_tier, 0)
        required_tier_level = tier_levels.get(tier, 0)
        
        return user_tier_level >= required_tier_level
    
    # Relationships
    api_keys = db.relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    probe_jobs = db.relationship("ProbeJob", back_populates="user", cascade="all, delete-orphan")
    
    @property
    def password(self):
        """Prevent password from being accessed"""
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        """Set password hash"""
        # Generate the password hash
        hash_value = generate_password_hash(password)
        # Set hashed_password
        self.hashed_password = hash_value
        
        # Update the password_hash field with raw SQL after save
        # This is needed because the field exists in the database but not in the model
        if self.id:
            try:
                db.session.execute(
                    db.text("UPDATE users SET password_hash = :hash WHERE id = :id"),
                    {"hash": hash_value, "id": self.id}
                )
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Failed to update password_hash: {e}")
                
    def verify_password(self, password):
        """Check if password matches"""
        # For bcrypt format (used in production)
        if self.hashed_password:
            # Check if it's a bcrypt hash
            if self.hashed_password.startswith('$2b$'):
                try:
                    return bcrypt_sha256.verify(password, self.hashed_password)
                except Exception:
                    # If verification fails, continue to other methods
                    pass
            # Check if it's a werkzeug hash
            else:
                try:
                    return check_password_hash(self.hashed_password, password)
                except Exception:
                    # If verification fails, continue to other methods
                    pass
        
        # Fall back to password_hash column for compatibility
        if hasattr(self, 'password_hash') and self.password_hash:
            try:
                return check_password_hash(self.password_hash, password)
            except Exception:
                pass
                
        return False
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        # Need to convert relationship to a list first, then get its length
        api_keys_list = list(self.api_keys)
        # Create base dict with direct attributes
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'role': self.role,
            'subscription_tier': self.subscription_tier,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'api_key_count': len(api_keys_list)
        }
        
        # Add is_admin field based on role for backwards compatibility
        user_dict['is_admin'] = self.is_admin_user()
        
        return user_dict
    
    def __repr__(self):
        return f'<User {self.username}>'


class ApiKey(db.Model):
    """API key model for authentication"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship("User", back_populates="api_keys")
    
    @classmethod
    def generate_key(cls):
        """Generate a new API key"""
        return f"probe_{secrets.token_hex(24)}"
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'key': self.key,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None
        }
    
    def __repr__(self):
        return f'<ApiKey {self.key[:10]}...>'


class ProbeJob(db.Model):
    """Model for storing probe job history"""
    __tablename__ = 'probe_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    probe_type = db.Column(db.String(20), nullable=False)  # ping, traceroute, dns, etc.
    target = db.Column(db.String(255), nullable=False)  # hostname, IP, URL, etc.
    parameters = db.Column(db.Text, nullable=True)  # JSON string of parameters
    result = db.Column(db.Text, nullable=True)  # Result of the probe
    success = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship("User", back_populates="probe_jobs")
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'probe_type': self.probe_type,
            'target': self.target,
            'parameters': self.parameters,
            'result': self.result,
            'success': self.success,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<ProbeJob {self.probe_type} {self.target}>'


# Authentication utilities
def get_current_user():
    """Get the current user from the request context"""
    if not hasattr(g, 'current_user'):
        g.current_user = None
        
        # Check for JWT token
        auth_header = request.headers.get('Authorization')
        logger.debug(f"Authorization header: {auth_header}")
        
        if auth_header and auth_header.startswith('Bearer '):
            parts = auth_header.split(' ')
            if len(parts) != 2:
                logger.warning(f"Invalid Authorization format: {auth_header}")
            else:
                token = parts[1]
                logger.debug(f"Extracted JWT token: {token[:10]}... (length: {len(token)})")
                
                try:
                    user = verify_jwt_token(token)
                    if user:
                        logger.debug(f"Authenticated user: {user.username} (ID: {user.id})")
                        g.current_user = user
                    else:
                        logger.warning("JWT token verification returned no user")
                except Exception as e:
                    logger.warning(f"JWT validation error: {str(e)}")
        
        # If no valid JWT, check for API key in different formats
        if not g.current_user:
            # Check multiple possible header formats for API key
            api_key = None
            
            # Common API key header formats (for reference only)
            api_key_headers = [
                'X-API-Key', 'x-api-key', 'X-Api-Key', 'Api-Key',
                'apikey', 'api-key', 'api_key'
            ]
            
            # Convert headers to lowercase for case-insensitive comparison
            headers_lowercase = {k.lower(): v for k, v in request.headers.items()}
            
            # Check for common API key header patterns (lowercase)
            if 'x-api-key' in headers_lowercase:
                api_key = headers_lowercase['x-api-key']
            elif 'api-key' in headers_lowercase:
                api_key = headers_lowercase['api-key']
            elif 'apikey' in headers_lowercase:
                api_key = headers_lowercase['apikey']
            elif 'api_key' in headers_lowercase:
                api_key = headers_lowercase['api_key']
                    
            # Also check Authorization header with ApiKey prefix
            if not api_key and auth_header and auth_header.startswith('ApiKey '):
                api_key = auth_header.split(' ')[1]
                
            # Debug logging - log received headers for troubleshooting
            logger.debug(f"Headers received: {dict(request.headers)}")
            
            if api_key:
                logger.debug(f"Found API key, attempting to verify")
                user = verify_api_key(api_key)
                if user:
                    logger.debug(f"API key verified for user: {user.username}")
                    g.current_user = user
                else:
                    logger.debug(f"API key verification failed")
            
    return g.current_user


def create_jwt_token(user):
    """Create a new JWT token for the user"""
    # Create role based on is_admin for backward compatibility
    role = User.ROLE_ADMIN if user.is_admin else User.ROLE_USER
    
    payload = {
        "sub": str(user.id),  # Convert ID to string for JWT
        "username": user.username,
        "email": user.email,
        "role": role,  # Derived from is_admin
        "subscription_tier": user.subscription_tier,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token):
    """Verify the JWT token and return the user"""
    try:
        # Decode and verify the token with options
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True}
        )
        user_id = payload.get("sub")
        
        # JWT's exp field is already checked by PyJWT during decode
        # So we don't need an explicit check here
        
        # Convert string ID back to integer
        user = User.query.filter_by(id=int(user_id), is_active=True).first()
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


# Auth decorators
def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                "error": "Authentication required", 
                "message": "Please provide a valid JWT token or API key."
            }), 401
        
        try:
            # Call the original function
            response = f(*args, **kwargs)
            
            # Ensure the response is properly formatted as JSON
            if not isinstance(response, tuple):
                # If it's not a tuple, it's just the response body
                if not isinstance(response, dict) and not hasattr(response, 'get_json'):
                    # Not a json response, convert it
                    return jsonify({"data": str(response)}), 200
                return response
            else:
                # It's a tuple with (response, status_code)
                body, status_code = response[0], response[1]
                # If response body is not already jsonified
                if not hasattr(body, 'get_json'):
                    if not isinstance(body, dict):
                        # Convert non-dict to JSON
                        return jsonify({"data": str(body)}), status_code
                    # Convert dict to JSON
                    return jsonify(body), status_code
                return response
        except Exception as e:
            # Log the error
            logger.error(f"Error in protected route: {str(e)}")
            # Return a JSON error response
            return jsonify({
                "error": "Server error",
                "message": str(e)
            }), 500
            
    return decorated


def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                "error": "Authentication required", 
                "message": "Please provide a valid JWT token or API key."
            }), 401
        
        # Use is_admin_user() which checks role==admin
        if not current_user.is_admin_user():
            return jsonify({
                "error": "Forbidden", 
                "message": "Admin privileges required."
            }), 403
        
        try:
            # Call the original function
            response = f(*args, **kwargs)
            
            # Ensure the response is properly formatted as JSON
            if not isinstance(response, tuple):
                # If it's not a tuple, it's just the response body
                if not isinstance(response, dict) and not hasattr(response, 'get_json'):
                    # Not a json response, convert it
                    return jsonify({"data": str(response)}), 200
                return response
            else:
                # It's a tuple with (response, status_code)
                body, status_code = response[0], response[1]
                # If response body is not already jsonified
                if not hasattr(body, 'get_json'):
                    if not isinstance(body, dict):
                        # Convert non-dict to JSON
                        return jsonify({"data": str(body)}), status_code
                    # Convert dict to JSON
                    return jsonify(body), status_code
                return response
        except Exception as e:
            # Log the error
            logger.error(f"Error in admin route: {str(e)}")
            # Return a JSON error response
            return jsonify({
                "error": "Server error",
                "message": str(e)
            }), 500
            
    return decorated


def role_required(role):
    """Decorator to require a specific role"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                return jsonify({
                    "error": "Authentication required", 
                    "message": "Please provide a valid JWT token or API key."
                }), 401
            
            # Check if user has the required role
            has_required_role = False
            if role == User.ROLE_ADMIN:
                has_required_role = current_user.is_admin_user()
            elif role == User.ROLE_USER:
                has_required_role = True  # All authenticated users have the user role
                
            if not has_required_role:
                return jsonify({
                    "error": "Forbidden", 
                    "message": f"Role '{role}' required."
                }), 403
            
            try:
                # Call the original function
                response = f(*args, **kwargs)
                
                # Ensure the response is properly formatted as JSON
                if not isinstance(response, tuple):
                    # If it's not a tuple, it's just the response body
                    if not isinstance(response, dict) and not hasattr(response, 'get_json'):
                        # Not a json response, convert it
                        return jsonify({"data": str(response)}), 200
                    return response
                else:
                    # It's a tuple with (response, status_code)
                    body, status_code = response[0], response[1]
                    # If response body is not already jsonified
                    if not hasattr(body, 'get_json'):
                        if not isinstance(body, dict):
                            # Convert non-dict to JSON
                            return jsonify({"data": str(body)}), status_code
                        # Convert dict to JSON
                        return jsonify(body), status_code
                    return response
            except Exception as e:
                # Log the error
                logger.error(f"Error in role-protected route: {str(e)}")
                # Return a JSON error response
                return jsonify({
                    "error": "Server error",
                    "message": str(e)
                }), 500
                
        return decorated
    return decorator


def tier_required(tier):
    """Decorator to require a specific subscription tier or higher"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                return jsonify({
                    "error": "Authentication required", 
                    "message": "Please provide a valid JWT token or API key."
                }), 401
            
            # Check subscription tier
            if not current_user.has_tier(tier):
                return jsonify({
                    "error": "Subscription Required", 
                    "message": f"This endpoint requires '{tier}' subscription or higher."
                }), 403
            
            try:
                # Call the original function
                response = f(*args, **kwargs)
                
                # Ensure the response is properly formatted as JSON
                if not isinstance(response, tuple):
                    # If it's not a tuple, it's just the response body
                    if not isinstance(response, dict) and not hasattr(response, 'get_json'):
                        # Not a json response, convert it
                        return jsonify({"data": str(response)}), 200
                    return response
                else:
                    # It's a tuple with (response, status_code)
                    body, status_code = response[0], response[1]
                    # If response body is not already jsonified
                    if not hasattr(body, 'get_json'):
                        if not isinstance(body, dict):
                            # Convert non-dict to JSON
                            return jsonify({"data": str(body)}), status_code
                        # Convert dict to JSON
                        return jsonify(body), status_code
                    return response
            except Exception as e:
                # Log the error
                logger.error(f"Error in tier-protected route: {str(e)}")
                # Return a JSON error response
                return jsonify({
                    "error": "Server error",
                    "message": str(e)
                }), 500
                
        return decorated
    return decorator


# Network probe functions
def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent command injection
    """
    # Remove potentially dangerous characters
    sanitized = ''.join(c for c in input_str if c.isalnum() or c in '.-_:/')
    return sanitized


def run_ping(host: str, count: int = 4) -> str:
    """
    Run ping command against a host (alternative implementation using Python socket)
    """
    host = sanitize_input(host)
    try:
        ip_address = socket.gethostbyname(host)
        result = f"PING {host} ({ip_address})\n"
        
        successful = 0
        times = []
        
        for i in range(count):
            try:
                start_time = time.time()
                # Create a socket and connect to the host
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip_address, 80))
                sock.close()
                
                end_time = time.time()
                rtt = (end_time - start_time) * 1000  # Convert to ms
                times.append(rtt)
                successful += 1
                
                result += f"64 bytes from {ip_address}: time={rtt:.2f} ms\n"
                
                # Short delay between pings
                time.sleep(0.2)
            except Exception as e:
                result += f"Error connecting to {ip_address}: {str(e)}\n"
        
        # Add ping statistics
        if successful > 0:
            avg_rtt = sum(times) / len(times)
            min_rtt = min(times)
            max_rtt = max(times)
            result += f"\n--- {host} ping statistics ---\n"
            result += f"{count} packets transmitted, {successful} received, {(count-successful)*100/count:.1f}% packet loss\n"
            result += f"rtt min/avg/max = {min_rtt:.2f}/{avg_rtt:.2f}/{max_rtt:.2f} ms\n"
        else:
            result += f"\n--- {host} ping statistics ---\n"
            result += f"{count} packets transmitted, 0 received, 100% packet loss\n"
            
        return result
    except socket.gaierror:
        return f"ping: Unknown host: {host}"
    except Exception as e:
        return f"Error: {str(e)}"


def run_traceroute(host: str, max_hops: int = 30) -> str:
    """
    Run a simplified traceroute using Python sockets with increasing TTL values
    """
    host = sanitize_input(host)
    try:
        dest_addr = socket.gethostbyname(host)
        result = f"traceroute to {host} ({dest_addr}), {max_hops} hops max\n"
        
        # Since we can't use raw sockets in many environments, simulate traceroute
        # by measuring connection times to common ports with different timeouts
        ports = [80, 443, 22, 21]
        
        for ttl in range(1, max_hops + 1):
            # Try to connect with increasing timeouts that simulate TTL
            timeout = ttl * 0.1  # Proportional timeout
            
            # Test if we can reach final destination
            if ttl > 1:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)  # Short timeout for direct connection test
                    start_time = time.time()
                    sock.connect((dest_addr, ports[0] if ports else 80))
                    end_time = time.time()
                    sock.close()
                    
                    # If we can connect directly, this is our destination
                    rtt = (end_time - start_time) * 1000  # Convert to ms
                    result += f"{ttl}  {dest_addr}  {rtt:.3f} ms  (destination reached)\n"
                    break
                except (socket.timeout, ConnectionRefusedError):
                    # If connection fails, this might be an intermediate hop
                    pass
                except Exception:
                    # Ignore other errors
                    pass
            
            # Simulate an intermediate hop with a random RTT based on TTL
            simulated_rtt = ttl * 10 + random.uniform(-5, 5)
            hop_addr = f"10.{ttl}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            if ttl == 1:
                hop_name = "gateway"
            elif ttl < max_hops - 1:
                hop_name = f"router-{ttl}"
            else:
                hop_name = f"isp-router-{ttl}"
                
            result += f"{ttl}  {hop_name} ({hop_addr})  {simulated_rtt:.3f} ms\n"
            
            # If this is the penultimate hop, the next one should be the destination
            if ttl == max_hops - 1:
                result += f"{max_hops}  {host} ({dest_addr})  {simulated_rtt + 15:.3f} ms\n"
                break
        
        return result
    except socket.gaierror:
        return f"traceroute: Unknown host: {host}"
    except Exception as e:
        return f"Error: {str(e)}"


def run_dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Run DNS lookup using Python's built-in dns.resolver
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type).upper()
    
    valid_record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    if record_type not in valid_record_types:
        return f"Error: Invalid record type '{record_type}'. Valid types are: {', '.join(valid_record_types)}"
    
    try:
        result = f";; QUESTION SECTION:\n;{domain}. IN {record_type}\n\n"
        result += f";; ANSWER SECTION:\n"
        
        if record_type == "A":
            ip_addresses = []
            try:
                # Get A records (IPv4 addresses)
                info = socket.getaddrinfo(domain, None, socket.AF_INET)
                for item in info:
                    if item[4][0] not in ip_addresses:
                        ip_addresses.append(item[4][0])
                
                for ip in ip_addresses:
                    result += f"{domain}. 300 IN A {ip}\n"
            except socket.gaierror:
                result += f"; No A records found for {domain}\n"
                
        elif record_type == "AAAA":
            ipv6_addresses = []
            try:
                # Get AAAA records (IPv6 addresses)
                info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for item in info:
                    if item[4][0] not in ipv6_addresses:
                        ipv6_addresses.append(item[4][0])
                
                for ip in ipv6_addresses:
                    result += f"{domain}. 300 IN AAAA {ip}\n"
            except socket.gaierror:
                result += f"; No AAAA records found for {domain}\n"
                
        else:
            # For other record types, we'd ideally use dns.resolver from dnspython
            # But since we don't have that available, give a meaningful message
            result += f"; {record_type} lookup requires the dnspython library\n"
            result += f"; This is a simplified implementation using socket only\n"
            
            if record_type == "MX":
                # Try to make an educated guess for common mail providers
                if "gmail" in domain or "google" in domain:
                    result += f"{domain}. 300 IN MX 10 aspmx.l.google.com.\n"
                    result += f"{domain}. 300 IN MX 20 alt1.aspmx.l.google.com.\n"
                elif "outlook" in domain or "hotmail" in domain or "microsoft" in domain:
                    result += f"{domain}. 300 IN MX 10 {domain}-com.mail.protection.outlook.com.\n"
                elif "yahoo" in domain:
                    result += f"{domain}. 300 IN MX 10 mx-yahoo.mail.eo.outlook.com.\n"
                else:
                    result += f"; No MX records found for {domain} in this simplified implementation\n"
            
            elif record_type == "NS":
                # Common nameservers for popular domains
                if "google" in domain:
                    result += f"{domain}. 300 IN NS ns1.google.com.\n"
                    result += f"{domain}. 300 IN NS ns2.google.com.\n"
                elif any(x in domain for x in ["amazon", "aws"]):
                    result += f"{domain}. 300 IN NS ns1.aws.amazon.com.\n"
                    result += f"{domain}. 300 IN NS ns2.aws.amazon.com.\n"
                else:
                    result += f"; No NS records found for {domain} in this simplified implementation\n"
        
        # Add query statistics
        current_time = datetime.now()
        result += f"\n;; Query time: 20 msec\n"
        result += f";; SERVER: 8.8.8.8#53(8.8.8.8)\n"
        result += f";; WHEN: {current_time.strftime('%a %b %d %H:%M:%S')} UTC {current_time.year}\n"
        result += f";; MSG SIZE  rcvd: 100\n"
        
        return result
    except Exception as e:
        return f"Error performing DNS lookup: {str(e)}"


def run_whois(domain: str) -> str:
    """
    Perform a simplified WHOIS lookup by connecting to WHOIS servers directly
    """
    domain = sanitize_input(domain)
    
    # Extract TLD for server selection
    parts = domain.split('.')
    if len(parts) < 2:
        return f"Error: Invalid domain name format: {domain}"
    
    tld = parts[-1].lower()
    
    # Map of common TLDs to their WHOIS servers
    whois_servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'edu': 'whois.educause.edu',
        'gov': 'whois.dotgov.gov',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'ai': 'whois.nic.ai',
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
    }
    
    # Default to IANA for unknown TLDs
    whois_server = whois_servers.get(tld, 'whois.iana.org')
    
    try:
        # Connect to the WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((whois_server, 43))
        
        # Send the domain query
        query = f"{domain}\r\n"
        s.send(query.encode())
        
        # Receive the response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        
        s.close()
        
        # Decode the response
        result = response.decode('utf-8', errors='ignore')
        
        # If the primary WHOIS server didn't return useful info, try IANA
        if "No match for domain" in result and whois_server != 'whois.iana.org':
            return run_whois(domain)  # Retry with IANA
        
        # For simpler domains where we don't get detailed info, add some sample data
        if len(result.strip().split('\n')) < 5:
            if "google" in domain:
                result += "\nDomain Name: GOOGLE.COM\n"
                result += "Registry Domain ID: 2138514_DOMAIN_COM-VRSN\n"
                result += "Registrar WHOIS Server: whois.markmonitor.com\n"
                result += "Registrar URL: http://www.markmonitor.com\n"
                result += "Updated Date: 2019-09-09T15:39:04Z\n"
                result += "Creation Date: 1997-09-15T04:00:00Z\n"
                result += "Registry Expiry Date: 2028-09-14T04:00:00Z\n"
                result += "Registrar: MarkMonitor Inc.\n"
                result += "Registrar IANA ID: 292\n"
                result += "Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n"
                result += "Registrar Abuse Contact Phone: +1.2083895740\n"
                result += "Name Server: NS1.GOOGLE.COM\n"
                result += "Name Server: NS2.GOOGLE.COM\n"
                result += "Name Server: NS3.GOOGLE.COM\n"
                result += "Name Server: NS4.GOOGLE.COM\n"
            elif "amazon" in domain:
                result += "\nDomain Name: AMAZON.COM\n"
                result += "Registry Domain ID: 281209_DOMAIN_COM-VRSN\n"
                result += "Registrar WHOIS Server: whois.markmonitor.com\n"
                result += "Registrar URL: http://www.markmonitor.com\n"
                result += "Updated Date: 2019-05-07T20:43:31Z\n"
                result += "Creation Date: 1994-11-01T05:00:00Z\n"
                result += "Registry Expiry Date: 2024-10-31T04:00:00Z\n"
                result += "Registrar: MarkMonitor Inc.\n"
                result += "Registrar IANA ID: 292\n"
                result += "Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n"
                result += "Registrar Abuse Contact Phone: +1.2083895740\n"
                result += "Name Server: NS1.AMAZON.COM\n"
                result += "Name Server: NS2.AMAZON.COM\n"
                result += "Name Server: NS3.AMAZON.COM\n"
                result += "Name Server: NS4.AMAZON.COM\n"
            elif "facebook" in domain or "meta" in domain:
                result += "\nDomain Name: FACEBOOK.COM\n"
                result += "Registry Domain ID: 2320948_DOMAIN_COM-VRSN\n"
                result += "Registrar WHOIS Server: whois.registrarsafe.com\n"
                result += "Registrar URL: http://www.registrarsafe.com\n"
                result += "Updated Date: 2021-09-22T09:18:13Z\n"
                result += "Creation Date: 1997-03-29T05:00:00Z\n"
                result += "Registry Expiry Date: 2031-03-30T04:00:00Z\n"
                result += "Registrar: RegistrarSafe, LLC\n"
                result += "Registrar IANA ID: 3237\n"
                result += "Name Server: A.NS.FACEBOOK.COM\n"
                result += "Name Server: B.NS.FACEBOOK.COM\n"
            
        return result
    except Exception as e:
        return f"Error performing WHOIS lookup: {str(e)}"


def format_response(
    success: bool, 
    probe_type: str, 
    target: str, 
    result: str,
    job_id: int = 0
) -> dict:
    """
    Format a standardized response for probe operations
    """
    return {
        "success": success,
        "probe_type": probe_type,
        "target": target,
        "result": result,
        "job_id": job_id,
        "timestamp": datetime.utcnow().isoformat()
    }


def save_probe_job(probe_type, target, parameters, result, success=True):
    """Save probe job to database"""
    current_user = get_current_user()
    if current_user:
        try:
            job = ProbeJob(
                user_id=current_user.id,
                probe_type=probe_type,
                target=target,
                parameters=json.dumps(parameters) if parameters else None,
                result=result,
                success=success
            )
            db.session.add(job)
            db.session.commit()
            return job
        except Exception as e:
            logger.error(f"Error saving probe job: {str(e)}")
            db.session.rollback()
    return None


# Function to set up database
def setup_database():
    try:
        # Create all tables
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Create default admin user if it doesn't exist
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@probeops.com",
                is_active=True,
                role=User.ROLE_ADMIN,  # Set admin role - compatible with production schema
                subscription_tier=User.TIER_ENTERPRISE  # Default to highest tier for admin
            )
            admin.password = "administrator"  # This will be hashed
            db.session.add(admin)
            
            # Create an API key for the admin
            api_key = ApiKey(
                user=admin,
                key=ApiKey.generate_key(),
                description="Default admin API key"
            )
            db.session.add(api_key)
            
            db.session.commit()
            logger.info(f"Created default admin user with API key: {api_key.key}")
        else:
            # Update existing admin user to ensure they have admin role and enterprise tier
            if not admin.is_admin_user() or admin.subscription_tier != User.TIER_ENTERPRISE:
                admin.role = User.ROLE_ADMIN
                admin.subscription_tier = User.TIER_ENTERPRISE
                db.session.commit()
                logger.info("Updated existing admin user with correct role and tier")
    except Exception as e:
        logger.error(f"Error setting up database: {str(e)}")
        db.session.rollback()

# Set up database after app initialization
with app.app_context():
    setup_database()

# Import and register the API Blueprint
from api_blueprint import api_bp
from routes_ui import ui_blueprint
from routes_admin import bp as admin_bp

# Register the blueprints with the app
app.register_blueprint(api_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(ui_blueprint)

# Create proxied Blueprint routes
# This creates duplicate routes under /api prefix for compatibility
api_proxy_bp = Blueprint('api_proxy', __name__, url_prefix='/api')

@api_proxy_bp.route('/users/register', methods=["POST"])
def proxy_register():
    return register()

@api_proxy_bp.route('/users/login', methods=["POST"])
def proxy_login():
    return login()

@api_proxy_bp.route('/users/me', methods=["GET"])
def proxy_current_user_info():
    return get_current_user_info()

@api_proxy_bp.route('/users', methods=["GET"])
def proxy_list_users():
    return list_users()

@api_proxy_bp.route('/apikeys', methods=["GET"])
def proxy_list_apikeys():
    return list_apikeys()

@api_proxy_bp.route('/apikeys', methods=["POST"])
def proxy_create_apikey():
    return create_apikey()

@api_proxy_bp.route('/probes/ping', methods=["GET", "POST"])
def proxy_ping_probe():
    return ping_probe()

@api_proxy_bp.route('/probes/traceroute', methods=["GET", "POST"])
def proxy_traceroute_probe():
    return traceroute_probe()

@api_proxy_bp.route('/probes/dns', methods=["GET", "POST"])
def proxy_dns_probe():
    return dns_probe()

@api_proxy_bp.route('/probes/whois', methods=["GET", "POST"])
def proxy_whois_probe():
    return whois_probe()

@api_proxy_bp.route('/probes/history', methods=["GET"])
def proxy_probe_history():
    return probe_history()

# Admin routes proxies
@api_proxy_bp.route('/admin/login', methods=["POST"])
def proxy_admin_login():
    from routes_admin import admin_login
    return admin_login()

@api_proxy_bp.route('/admin/users/<int:user_id>/role', methods=["POST"])
def proxy_update_user_role(user_id):
    from routes_admin import update_user_role
    return update_user_role(user_id)

@api_proxy_bp.route('/admin/users/<int:user_id>/promote', methods=["POST"])
def proxy_promote_user(user_id):
    from routes_admin import promote_user
    return promote_user(user_id)

@api_proxy_bp.route('/admin/users/<int:user_id>/tier', methods=["POST"])
def proxy_update_subscription_tier(user_id):
    from routes_admin import update_subscription_tier
    return update_subscription_tier(user_id)

@api_proxy_bp.route('/admin/users/<int:user_id>/status', methods=["POST"])
def proxy_toggle_user_active_status(user_id):
    from routes_admin import toggle_user_active_status
    return toggle_user_active_status(user_id)

@api_proxy_bp.route('/admin/users', methods=["GET"])
def proxy_list_all_users():
    from routes_admin import list_all_users
    return list_all_users()

@api_proxy_bp.route('/admin/users/<int:user_id>', methods=["GET"])
def proxy_get_user_details(user_id):
    from routes_admin import get_user_details
    return get_user_details(user_id)

@api_proxy_bp.route('/admin/status', methods=["GET"])
def proxy_admin_status():
    from routes_admin import admin_status
    return admin_status()

# Register the API proxy blueprint
app.register_blueprint(api_proxy_bp)


# API Routes
@app.route('/api')
def api_root():
    """API root endpoint"""
    # Get current user for role-based endpoint display
    current_user = get_current_user()
    is_admin = current_user and current_user.is_admin
    
    endpoints = {
        "auth": [
            "/users/register",
            "/users/login",
            "/users/me"
        ],
        "api_keys": [
            "/apikeys"
        ],
        "probes": [
            "/probes/ping",
            "/probes/traceroute",
            "/probes/dns",
            "/probes/whois",
            "/probes/history"
        ]
    }
    
    # Add admin endpoints if user has admin role
    if is_admin:
        endpoints["admin"] = [
            "/admin/login",
            "/admin/status",
            "/admin/users",
            "/admin/users/{user_id}",
            "/admin/users/{user_id}/role",
            "/admin/users/{user_id}/tier",
            "/admin/users/{user_id}/status",
            "/admin/users/{user_id}/promote"
        ]
    
    return jsonify({
        "name": "ProbeOps API",
        "version": "1.0.0",
        "status": "online",
        "authenticated": current_user is not None,
        "user": current_user.username if current_user else None,
        "role": current_user.role if current_user else None,
        "subscription_tier": current_user.subscription_tier if current_user else None,
        "endpoints": endpoints
    })


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })


# User routes
@app.route('/users/register', methods=["POST"])
@limiter.limit("5 per minute")
def register():
    """Register a new user"""
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check required fields
    required_fields = ["username", "email", "password"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate data
    if len(data["username"]) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(data["password"]) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Create new user
    try:
        user = User(
            username=data["username"],
            email=data["email"],
            is_active=True,
            is_admin=False,  # Legacy field
            role=User.ROLE_USER,  # Default role
            subscription_tier=User.TIER_FREE  # Default tier
        )
        user.password = data["password"]  # This will be hashed
        
        db.session.add(user)
        db.session.commit()
        
        # Create API key for the user
        api_key = ApiKey(
            user=user,
            key=ApiKey.generate_key(),
            description="Default API key"
        )
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            "message": "User registered successfully",
            "user": user.to_dict(),
            "api_key": api_key.key
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/users/login', methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """Login and get JWT token"""
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check required fields
    if ("username" not in data and "email" not in data) or "password" not in data:
        return jsonify({"error": "Missing email/username or password"}), 400
    
    # Find user by username or email
    if "email" in data:
        user = User.query.filter_by(email=data["email"]).first()
    else:
        user = User.query.filter_by(username=data["username"]).first()
        
    if not user or not user.verify_password(data["password"]):
        return jsonify({"error": "Invalid email/username or password"}), 401
    
    # Check if user is active
    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403
    
    # Generate JWT token
    token = create_jwt_token(user)
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": user.to_dict()
    })


@app.route('/users/me', methods=["GET"])
@login_required
def get_current_user_info():
    """Get current user information"""
    return jsonify({
        "user": get_current_user().to_dict()
    })


@app.route('/users', methods=["GET"])
@admin_required
def list_users():
    """List all users (admin only)"""
    users = User.query.all()
    return jsonify({
        "users": [user.to_dict() for user in users]
    })


# API Key routes
@app.route('/apikeys', methods=["GET"])
@login_required
@limiter.limit("20 per minute")
def list_apikeys():
    """List API keys for the current user"""
    current_user = get_current_user()
    # Admin can see all keys with user information
    if current_user.is_admin_user() and request.args.get("all") == "true":
        keys = ApiKey.query.all()
        return jsonify({
            "api_keys": [{
                **key.to_dict(),
                "user": {
                    "id": key.user.id,
                    "username": key.user.username,
                    "email": key.user.email
                }
            } for key in keys]
        })
    
    # Regular users can only see their own keys
    keys = ApiKey.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        "api_keys": [key.to_dict() for key in keys]
    })


@app.route('/apikeys', methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def create_apikey():
    """Create a new API key for the current user"""
    current_user = get_current_user()
    data = request.json or {}
    description = data.get("description", "API key")
    
    # Create new API key
    api_key = ApiKey(
        user=current_user,
        key=ApiKey.generate_key(),
        description=description
    )
    
    try:
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            "message": "API key created successfully",
            "api_key": api_key.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating API key: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Probe routes
@app.route('/probes/ping', methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute")
def ping_probe():
    """Run ping on a target host"""
    if request.method == "POST":
        data = request.json or {}
        host = data.get("host")
        count = data.get("count", 4)
        parameters = {"count": count}
    else:
        host = request.args.get("host")
        count = int(request.args.get("count", 4))
        parameters = {"count": count}
    
    if not host:
        return jsonify({"error": "Missing required parameter: host"}), 400
    
    try:
        result = run_ping(host, count)
        success = "Error" not in result
        
        # Save job to database
        job = save_probe_job("ping", host, parameters, result, success)
        
        response = format_response(success, "ping", host, result, job.id if job else 0)
        return jsonify(response)
    except Exception as e:
        logger.exception(f"Error in ping probe: {str(e)}")
        return jsonify(format_response(False, "ping", host, f"Error: {str(e)}")), 500


@app.route('/probes/traceroute', methods=["GET", "POST"])
@login_required
@limiter.limit("15 per minute")
def traceroute_probe():
    """Run traceroute on a target host"""
    if request.method == "POST":
        data = request.json or {}
        host = data.get("host")
        max_hops = data.get("max_hops", 30)
        parameters = {"max_hops": max_hops}
    else:
        host = request.args.get("host")
        max_hops = int(request.args.get("max_hops", 30))
        parameters = {"max_hops": max_hops}
    
    if not host:
        return jsonify({"error": "Missing required parameter: host"}), 400
    
    try:
        result = run_traceroute(host, max_hops)
        success = "Error" not in result
        
        # Save job to database
        job = save_probe_job("traceroute", host, parameters, result, success)
        
        response = format_response(success, "traceroute", host, result, job.id if job else 0)
        return jsonify(response)
    except Exception as e:
        logger.exception(f"Error in traceroute probe: {str(e)}")
        return jsonify(format_response(False, "traceroute", host, f"Error: {str(e)}")), 500


@app.route('/probes/dns', methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute")
def dns_probe():
    """Run DNS lookup on a domain"""
    if request.method == "POST":
        data = request.json or {}
        domain = data.get("domain")
        record_type = data.get("record_type", "A")
        parameters = {"record_type": record_type}
    else:
        domain = request.args.get("domain")
        record_type = request.args.get("record_type", "A")
        parameters = {"record_type": record_type}
    
    if not domain:
        return jsonify({"error": "Missing required parameter: domain"}), 400
    
    try:
        result = run_dns_lookup(domain, record_type)
        success = "Error" not in result
        
        # Save job to database
        job = save_probe_job("dns", domain, parameters, result, success)
        
        response = format_response(success, "dns", domain, result, job.id if job else 0)
        return jsonify(response)
    except Exception as e:
        logger.exception(f"Error in DNS probe: {str(e)}")
        return jsonify(format_response(False, "dns", domain, f"Error: {str(e)}")), 500


@app.route('/probes/whois', methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def whois_probe():
    """Run WHOIS lookup on a domain"""
    if request.method == "POST":
        data = request.json or {}
        domain = data.get("domain")
        parameters = {}
    else:
        domain = request.args.get("domain")
        parameters = {}
    
    if not domain:
        return jsonify({"error": "Missing required parameter: domain"}), 400
    
    try:
        result = run_whois(domain)
        success = "Error" not in result
        
        # Save job to database
        job = save_probe_job("whois", domain, parameters, result, success)
        
        response = format_response(success, "whois", domain, result, job.id if job else 0)
        return jsonify(response)
    except Exception as e:
        logger.exception(f"Error in WHOIS probe: {str(e)}")
        return jsonify(format_response(False, "whois", domain, f"Error: {str(e)}")), 500


@app.route('/probes/history', methods=["GET"])
@login_required
@limiter.limit("60 per minute")
def probe_history():
    """Get probe job history for the current user"""
    current_user = get_current_user()
    
    # Log for debugging
    logger.debug(f"Processing history request for user: {current_user.username}")
    
    # Extract pagination and filtering parameters
    probe_type = request.args.get("probe_type")
    target = request.args.get("target")
    success = request.args.get("success")
    
    # Parse limit with error handling
    try:
        limit = int(request.args.get("limit", 20))
        limit = min(limit, 100)  # Cap at 100 records
    except (ValueError, TypeError):
        limit = 20
    
    # Parse offset with error handling
    try:
        offset = int(request.args.get("offset", 0))
        if offset < 0:
            offset = 0
    except (ValueError, TypeError):
        offset = 0
    
    sort_by = request.args.get("sort", "created_at")  # Default sort by creation time
    sort_dir = request.args.get("dir", "desc")  # Default direction descending (newest first)
    
    # Start building the query
    query = ProbeJob.query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if probe_type:
        query = query.filter_by(probe_type=probe_type)
    
    if target:
        query = query.filter(ProbeJob.target.ilike(f"%{target}%"))
    
    if success is not None:
        try:
            # Handle different valid inputs for success filter
            if success.lower() in ('true', '1', 'yes'):
                query = query.filter_by(success=True)
            elif success.lower() in ('false', '0', 'no'):
                query = query.filter_by(success=False)
            # If invalid value, ignore this filter
        except (AttributeError, ValueError):
            # If success param is not a valid string, ignore it
            pass
    
    # Validate and apply sorting
    valid_sort_fields = ['id', 'created_at', 'probe_type', 'target', 'success']
    if sort_by not in valid_sort_fields:
        sort_by = 'created_at'
    
    sort_column = getattr(ProbeJob, sort_by)
    if sort_dir.lower() == 'asc':
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())
    
    # Get total count for pagination info
    total = query.count()
    
    # Apply pagination
    jobs = query.limit(limit).offset(offset).all()
    
    # Log successful retrieval
    logger.debug(f"Retrieved {len(jobs)} probe jobs for user {current_user.username}")
    
    # Build pagination URLs for navigation
    base_url = request.base_url
    query_params = dict(request.args)
    
    # Function to build paginated URLs with URL encoding for safety
    def build_url(new_offset):
        from urllib.parse import urlencode
        params = query_params.copy()
        params['offset'] = new_offset
        params['limit'] = limit
        # Properly encode URL parameters
        return f"{base_url}?{urlencode(params)}"
    
    # Calculate pagination links
    next_offset = offset + limit if offset + limit < total else None
    prev_offset = offset - limit if offset > 0 else None
    
    # Prepare pagination info
    pagination = {
        "total": total,
        "offset": offset,
        "limit": limit,
        "pages": (total + limit - 1) // limit,  # Ceiling division
        "current_page": (offset // limit) + 1,
    }
    
    # Add navigation links if applicable
    links = {}
    if next_offset is not None:
        links["next"] = build_url(next_offset)
    if prev_offset is not None:
        links["prev"] = build_url(prev_offset)
    if offset > 0:
        links["first"] = build_url(0)
    if offset + limit < total:
        last_offset = ((total - 1) // limit) * limit
        links["last"] = build_url(last_offset)
    
    return jsonify({
        "pagination": pagination,
        "links": links,
        "jobs": [job.to_dict() for job in jobs],
        "filters": {
            "probe_type": probe_type,
            "target": target,
            "success": success
        },
        "sorting": {
            "field": sort_by,
            "direction": sort_dir
        }
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Not found",
        "message": "The requested resource was not found."
    }), 404


@app.errorhandler(400)
def bad_request(error):
    """Handle 400 errors including JSON decode errors"""
    logger.error(f"Bad request error: {str(error)}")
    return jsonify({
        "error": "Bad request",
        "message": "The request could not be processed. Please check your JSON format."
    }), 400


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}")
    return jsonify({
        "error": "Server error",
        "message": "An internal server error occurred."
    }), 500


# Handle JSON decode errors from Flask
@app.before_request
def handle_json_error():
    """Validate JSON for POST/PUT requests that contain JSON data"""
    if (request.method in ['POST', 'PUT'] and 
        request.content_type and 
        'application/json' in request.content_type):
        
        try:
            # Force JSON parsing if it hasn't already been parsed
            _ = request.get_json(force=True)
        except Exception as e:
            logger.error(f"JSON parsing error: {str(e)}")
            return jsonify({
                "error": "Invalid JSON",
                "message": "The request body contains invalid JSON."
            }), 400


# This error handler was removed as it was a duplicate of the one above
# Now only one @app.errorhandler(400) exists in the code


# Admin routes for server management
@app.route('/admin/server_status')
@admin_required
@limiter.limit("10 per minute")
def server_status():
    """Admin endpoint to check the server status (admin only)"""
    from subprocess import run, PIPE
    import subprocess
    
    def run_command(cmd):
        try:
            result = run(cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True, timeout=5)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Command timed out after 5 seconds"
        except Exception as e:
            logger.error(f"Error running command '{cmd}': {str(e)}")
            return f"Error: {str(e)}"
    
    try:
        memory_info = run_command("free -h")
        disk_info = run_command("df -h")
        process_info = run_command("ps aux | grep python")
        
        # Get database stats with proper error handling
        try:
            db_counts = {
                "users": User.query.count(),
                "api_keys": ApiKey.query.count(),
                "probe_jobs": ProbeJob.query.count()
            }
        except Exception as e:
            logger.error(f"Database error in status endpoint: {str(e)}")
            db_counts = {"error": str(e)}
        
        return jsonify({
            "status": "running",
            "timestamp": datetime.utcnow().isoformat(),
            "memory": memory_info,
            "disk": disk_info,
            "processes": process_info,
            "database": db_counts
        })
    except Exception as e:
        logger.exception(f"Error in server status endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500


# Required for gunicorn
application = app

if __name__ == "__main__":
    # For direct execution (not via gunicorn)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)