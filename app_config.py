"""
Flask application configuration for ProbeOps API
"""
import os
import logging

from flask import Flask
from flask_cors import CORS

from models import db, User, ApiKey, ProbeJob

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configure application
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "probeops_development_secret")
    
    # Database configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Configure CORS
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Initialize extensions
    db.init_app(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        # Create default admin user if it doesn't exist
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@probeops.com",
                is_active=True,
                is_admin=True
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
    
    return app