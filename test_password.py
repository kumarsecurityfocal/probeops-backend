#!/usr/bin/env python3
"""
Test script to verify password verification
"""
import sys
import logging
from passlib.hash import bcrypt_sha256
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Import from flask_server directly
from flask_server import app, db, User

def test_user_auth(email, password):
    """Test password verification for a user"""
    with app.app_context():
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            logger.error(f"User not found: {email}")
            return False
        
        logger.info(f"Found user: {user.username}, Email: {user.email}")
        logger.info(f"Password hash: {user.hashed_password[:30]}...")
        
        # Try different verification methods
        try:
            # Try werkzeug check_password_hash first
            if user.hashed_password and check_password_hash(user.hashed_password, password):
                logger.info("Password verified using werkzeug check_password_hash")
                return True
        except Exception as e:
            logger.warning(f"Failed to verify with check_password_hash: {e}")
        
        try:
            # Try bcrypt_sha256 verification
            if user.hashed_password and user.hashed_password.startswith('$2b$'):
                if bcrypt_sha256.verify(password, user.hashed_password):
                    logger.info("Password verified using bcrypt_sha256.verify")
                    return True
        except Exception as e:
            logger.warning(f"Failed to verify with bcrypt_sha256: {e}")
        
        # Try password_hash field if it exists
        if hasattr(user, 'password_hash') and user.password_hash:
            try:
                if check_password_hash(user.password_hash, password):
                    logger.info("Password verified using password_hash field")
                    return True
            except Exception as e:
                logger.warning(f"Failed to verify with password_hash: {e}")
        
        logger.error("All password verification methods failed")
        return False

def main():
    """Main entry point"""
    if len(sys.argv) < 3:
        print("Usage: python test_password.py <email> <password>")
        return 1
    
    email = sys.argv[1]
    password = sys.argv[2]
    
    logger.info(f"Testing authentication for user: {email}")
    result = test_user_auth(email, password)
    
    if result:
        logger.info("Authentication SUCCESSFUL")
        return 0
    else:
        logger.error("Authentication FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())