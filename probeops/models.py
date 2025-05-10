"""
Database models for ProbeOps API
"""
import secrets
import logging
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash
# Import bcrypt directly for native hash verification
import bcrypt
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from probeops.app import db

# Configure logging
logger = logging.getLogger(__name__)

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    # Constants for roles and tiers
    ROLE_USER = 'user'
    ROLE_ADMIN = 'admin'
    
    TIER_FREE = 'Free'
    TIER_STANDARD = 'Standard'
    TIER_ENTERPRISE = 'Enterprise'
    
    VALID_TIERS = [TIER_FREE, TIER_STANDARD, TIER_ENTERPRISE]
    VALID_ROLES = [ROLE_USER, ROLE_ADMIN]
    
    # Database columns
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    # Note: password_hash column was removed (May 2025) as part of standardizing 
    # on the bcrypt-based hashed_password field for all authentication
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default=ROLE_USER)
    subscription_tier = Column(String(20), default=TIER_FREE)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    probe_jobs = relationship("ProbeJob", back_populates="user", cascade="all, delete-orphan")
    
    @property
    def password(self):
        """Prevent password from being accessed"""
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        """Set password hash"""
        # Generate the password hash using werkzeug's method
        hash_value = generate_password_hash(password)
        # Set hashed_password
        self.hashed_password = hash_value
    
    def verify_password(self, password):
        """Check if password matches"""
        # If no password hash is set, verification fails
        if not self.hashed_password:
            logger.warning(f"Password verification failed for user {self.username}: No hash set")
            return False
        
        # Add detailed logging for easier debugging
        logger.debug(f"Verifying password for user {self.username}")
        logger.debug(f"Password hash type: {self.hashed_password[:20]}")
        logger.debug(f"Actual input password: {password[:3]}***{password[-2:] if len(password) > 2 else ''}")
            
        try:
            # For werkzeug's standard formats (pbkdf2, scrypt)
            if self.hashed_password.startswith(('pbkdf2:', 'scrypt:')):
                verified = check_password_hash(self.hashed_password, password)
                logger.debug(f"Werkzeug verification result: {verified}")
                return verified
                
            # For bcrypt hashes
            elif self.hashed_password.startswith('$2'):
                # Import bcrypt directly to handle native bcrypt hashes
                import bcrypt
                # Convert strings to bytes for bcrypt
                encoded_password = password.encode('utf-8')
                encoded_hash = self.hashed_password.encode('utf-8')
                verified = bcrypt.checkpw(encoded_password, encoded_hash)
                logger.debug(f"Bcrypt verification result: {verified}")
                return verified
                
            # For any other hash type
            else:
                logger.debug(f"Using fallback verification method")
                verified = check_password_hash(self.hashed_password, password)
                logger.debug(f"Fallback verification result: {verified}")
                return verified
                
        except Exception as e:
            # Log the specific error but don't expose it
            logger.error(f"Password verification error for user {self.username}: {str(e)}")
            return False
    
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
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        # Count API keys and probe jobs
        api_key_count = len(list(self.api_keys)) if self.api_keys else 0
        probe_job_count = len(list(self.probe_jobs)) if self.probe_jobs else 0
        
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'role': self.role,
            'is_admin': self.is_admin_user(),  # For backward compatibility
            'subscription_tier': self.subscription_tier,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'api_key_count': api_key_count,
            'probe_job_count': probe_job_count
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class ApiKey(db.Model):
    """API key model for authentication"""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    key = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(100))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    @classmethod
    def generate_key(cls):
        """Generate a new API key"""
        return secrets.token_urlsafe(48)  # Generates a 64-char URL-safe token
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'key': self.key,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'user_id': self.user_id
        }
    
    def __repr__(self):
        return f'<ApiKey {self.id} for User {self.user_id}>'


class RateLimitConfig(db.Model):
    """Model for storing rate limit configurations by user tier"""
    __tablename__ = 'rate_limit_configs'
    
    id = Column(Integer, primary_key=True)
    tier = Column(String(20), unique=True, nullable=False)  # Free, Standard, Enterprise
    
    # Limits
    daily_limit = Column(Integer, nullable=False)
    monthly_limit = Column(Integer, nullable=False)
    
    # Min time between requests
    min_interval_minutes = Column(Integer, nullable=False)
    
    # Meta
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'tier': self.tier,
            'daily_limit': self.daily_limit,
            'monthly_limit': self.monthly_limit,
            'min_interval_minutes': self.min_interval_minutes,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'updated_by_user_id': self.updated_by_user_id
        }
    
    @classmethod
    def get_default_configs(cls):
        """Get default rate limit configurations"""
        return [
            cls(tier=User.TIER_FREE, daily_limit=100, monthly_limit=1000, min_interval_minutes=15),
            cls(tier=User.TIER_STANDARD, daily_limit=500, monthly_limit=5000, min_interval_minutes=5),
            cls(tier=User.TIER_ENTERPRISE, daily_limit=1000, monthly_limit=10000, min_interval_minutes=1)
        ]
    
    def __repr__(self):
        return f'<RateLimitConfig {self.tier}>'


class ProbeJob(db.Model):
    """Model for storing probe job history"""
    __tablename__ = 'probe_jobs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    probe_type = Column(String(20), nullable=False)  # ping, traceroute, dns, etc.
    target = Column(String(255), nullable=False)  # hostname, IP, URL, etc.
    parameters = Column(Text, nullable=True)  # JSON string of parameters
    result = Column(Text, nullable=True)  # Result of the probe
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="probe_jobs")
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'probe_type': self.probe_type,
            'target': self.target,
            'parameters': self.parameters,
            'result': self.result,
            'success': self.success,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<ProbeJob {self.id} ({self.probe_type}) for User {self.user_id}>'