"""
Flask application for ProbeOps API
"""
import os
import logging
from datetime import datetime
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


# Initialize extensions
db = SQLAlchemy(model_class=Base)
migrate = Migrate()


# Initialize database functions are defined in the create_app function


def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Set configuration from environment variables
    app.config.update(
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            'pool_recycle': 300,
            'pool_pre_ping': True,
        },
        JSON_SORT_KEYS=False,
    )
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Configure CORS
    cors_origins = [
        'https://probeops.com',
        'https://www.probeops.com',
        'http://localhost:3000',
        'http://localhost:8080',
    ]
    
    # Allow all origins in development mode
    if app.debug:
        cors_origins = ['*']
    
    logger.info(f"Configuring CORS with origins: {cors_origins}")
    CORS(app, resources={r"/api/*": {"origins": cors_origins}})
    
    # Configure rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
    
    # Request logging middleware
    @app.before_request
    def log_request_info():
        """Log detailed information about incoming requests"""
        # Generate a unique request ID for tracking
        request_id = os.urandom(4).hex()
        request.request_id = request_id
        
        # Log basic request info
        logger.info(f"[{request_id}] Request: {request.method} {request.path} - IP: {request.remote_addr}, Auth: {get_auth_type()}, Content-Type: {request.content_type}, User-Agent: {request.user_agent}")
        
        # Log query parameters if present
        if request.args:
            logger.debug(f"[{request_id}] Query params: {dict(request.args)}")
        
        # Log Authorization header (safely)
        auth_header = request.headers.get('Authorization')
        logger.debug(f"Authorization header: {mask_auth_header(auth_header)}")
        
        # Log all headers for debugging (but mask sensitive ones)
        logger.debug(f"Headers received: {request.headers}")
    
    # Response logging middleware
    @app.after_request
    def log_response_info(response):
        """Log information about the response"""
        # Add custom headers
        response.headers['X-ProbeOps-API'] = 'v1.0'
        
        # Add request ID to response
        if hasattr(request, 'request_id'):
            response.headers['X-Request-ID'] = request.request_id
            logger.info(f"[{request.request_id}] Response: {response.status_code} {request.method} {request.path}")
            logger.debug(f"[{request.request_id}] Response headers: {dict(response.headers)}")
        
        return response
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource was not found."
        }), 404
    
    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 errors"""
        logger.error(f"Server error: {error}", exc_info=True)
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred."
        }), 500
    
    # Setup database
    with app.app_context():
        # Import models to ensure they're registered with SQLAlchemy
        from probeops.models import User, ApiKey, ProbeJob, RateLimitConfig
        
        # Create tables
        db.create_all()
        
        # Initialize rate limit configurations if empty
        if RateLimitConfig.query.count() == 0:
            db.session.add_all(RateLimitConfig.get_default_configs())
            db.session.commit()
            logger.info("Default rate limit configurations created")
        
        # Setup test users if they don't exist
        if User.query.filter_by(email='admin@probeops.com').first() is None:
            logger.info("Creating default test users for API testing")
            
            # Create admin user
            admin = User(
                username='admin',
                email='admin@probeops.com',
                role=User.ROLE_ADMIN,
                subscription_tier=User.TIER_ENTERPRISE,
                is_active=True,
                created_at=datetime.utcnow()
            )
            admin.password = 'testpass123'  # This will set both password fields correctly
            db.session.add(admin)
            
            # Create a standard user as well
            standard_user = User(
                username='standard',
                email='standard@probeops.com',
                role=User.ROLE_USER,
                subscription_tier=User.TIER_STANDARD,
                is_active=True,
                created_at=datetime.utcnow()
            )
            standard_user.password = 'testpass123'
            db.session.add(standard_user)
            
            db.session.commit()
            logger.info("Test users created successfully")
        
        logger.info("Database tables created successfully")
    
    # Register API routes
    from probeops.routes import register_routes
    register_routes(app)
    
    return app


def get_auth_type():
    """Get the authentication type from request headers"""
    if request.headers.get('Authorization'):
        if request.headers.get('Authorization').startswith('Bearer '):
            return 'JWT'
        return 'Auth Header'
    elif request.headers.get('X-API-Key'):
        return 'API Key'
    return 'No Auth'


def mask_auth_header(auth_header):
    """Mask the authentication header for safe logging"""
    if not auth_header:
        return None
    
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        return f"Bearer {token[:5]}...{token[-5:]}" if len(token) > 10 else "Bearer [MASKED]"
    
    return "[MASKED]"