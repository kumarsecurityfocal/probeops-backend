"""
Database models for ProbeOps API
"""
import os
import secrets
import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt_sha256
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


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
    
    # Tell SQLAlchemy to only load specific columns
    __mapper_args__ = {
        'column_prefix': '_',
        'include_properties': ['id', 'username', 'email', 'hashed_password', 'is_active', 
                             'is_admin', 'role', 'subscription_tier', 'created_at']
    }
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    # Only include the primary password field in queries
    hashed_password = db.Column(db.String(256), nullable=False)
    # Don't include password_hash in model queries, but it still exists in DB
    # password_hash = db.Column(db.String(256))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)  # Legacy field, kept for backward compatibility
    role = db.Column(db.String(20), default=ROLE_USER)
    subscription_tier = db.Column(db.String(20), default=TIER_FREE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
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
        # Only set hashed_password since we're not using password_hash in queries
        self.hashed_password = hash_value
        
        # Manual SQL update to set password_hash in the database directly
        # This avoids SQLAlchemy trying to select the column in queries
        with db.engine.connect() as conn:
            conn.execute(
                db.text("UPDATE users SET password_hash = :hash WHERE id = :id"),
                {"hash": hash_value, "id": self.id if self.id else 0}
            )
            conn.commit()
    
    def verify_password(self, password):
        """Check if password matches"""
        # Only use hashed_password since we're not loading password_hash
        if self.hashed_password:
            return check_password_hash(self.hashed_password, password)
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
        # Need to convert relationship to a list first, then get its length
        api_keys_list = list(self.api_keys)
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,  # Legacy field, kept for backward compatibility
            'role': self.role,
            'subscription_tier': self.subscription_tier,
            'created_at': self.created_at.isoformat(),
            'api_key_count': len(api_keys_list)
        }
    
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


class RateLimitConfig(db.Model):
    """Model for storing rate limit configurations by user tier"""
    __tablename__ = 'rate_limit_configs'
    
    id = db.Column(db.Integer, primary_key=True)
    tier = db.Column(db.String(20), unique=True, nullable=False)  # Free, Standard, Enterprise
    
    # Daily and monthly request limits
    daily_limit = db.Column(db.Integer, nullable=False)
    monthly_limit = db.Column(db.Integer, nullable=False)
    
    # Minimum time between probe requests (in minutes)
    min_interval_minutes = db.Column(db.Integer, nullable=False)
    
    # When this configuration was last updated
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'tier': self.tier,
            'daily_limit': self.daily_limit,
            'monthly_limit': self.monthly_limit,
            'min_interval_minutes': self.min_interval_minutes,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def get_default_configs(cls):
        """Get default rate limit configurations"""
        return [
            # Free tier
            {
                'tier': User.TIER_FREE,
                'daily_limit': 100,
                'monthly_limit': 1000,
                'min_interval_minutes': 15
            },
            # Standard tier
            {
                'tier': User.TIER_STANDARD,
                'daily_limit': 500,
                'monthly_limit': 5000,
                'min_interval_minutes': 5
            },
            # Enterprise tier
            {
                'tier': User.TIER_ENTERPRISE,
                'daily_limit': 1000,
                'monthly_limit': 10000,
                'min_interval_minutes': 5
            }
        ]
    
    def __repr__(self):
        return f'<RateLimitConfig {self.tier}>'


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