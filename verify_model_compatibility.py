#!/usr/bin/env python3
"""
Script to verify model compatibility with Flask-Migrate
"""
import sys
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a simple test app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Import models from your application
from probeops.models import User, ApiKey, ProbeJob

def verify_models():
    """Verify model definitions and compatibility columns"""
    with app.app_context():
        # Create tables in memory
        db.create_all()
        
        # Check User model fields
        user_columns = User.__table__.columns.keys()
        logger.info(f"User model columns: {', '.join(user_columns)}")
        
        # Verify required fields
        # password_hash field removed after schema cleanup (May 2025)
        assert 'hashed_password' in user_columns, "hashed_password column is missing"
        
        # Verify model methods
        test_user = User(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        # Check password setting
        # password_hash field removed after schema cleanup (May 2025)
        assert test_user.hashed_password is not None, "hashed_password not set"
        
        # Check role-based admin detection
        assert not test_user.is_admin_user(), "New user should not be an admin"
        test_user.role = 'admin'
        assert test_user.is_admin_user(), "Admin role not detected correctly"
        
        # Verify to_dict method
        user_dict = test_user.to_dict()
        assert 'is_admin' in user_dict, "is_admin field missing from serialized user"
        assert user_dict['is_admin'] is True, "is_admin should be True for admin user"
        
        logger.info("All model compatibility checks passed!")
        return True

if __name__ == "__main__":
    try:
        success = verify_models()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        sys.exit(1)