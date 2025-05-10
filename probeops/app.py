"""
Flask application factory for ProbeOps API
"""
import os
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables from .env file if present
from dotenv import load_dotenv
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Create database base class
class Base(DeclarativeBase):
    pass

# Create database instance
db = SQLAlchemy(model_class=Base)

def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configure the app
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL"),
        SQLALCHEMY_ENGINE_OPTIONS={
            "pool_recycle": 300,
            "pool_pre_ping": True,
        },
        # Enable CORS
        CORS_ORIGINS=os.environ.get("CORS_ORIGINS", "").split(",") or ["*"],
    )
    
    # Allow CORS for all routes
    CORS(app)
    
    # Initialize database with the app
    db.init_app(app)
    
    # Import models here to ensure they are registered with SQLAlchemy
    # This must be imported after db is defined
    from probeops.models import User, ApiKey, ProbeJob, RateLimitConfig
    
    # Import and register routes
    from probeops.routes import register_routes
    register_routes(app)
    
    @app.route('/')
    def index():
        """Root endpoint"""
        return jsonify({
            "name": "ProbeOps API",
            "version": "1.0.0",
            "status": "running",
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    @app.route('/api/health')
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    return app