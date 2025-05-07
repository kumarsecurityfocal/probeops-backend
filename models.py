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
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
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
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        """Check if password matches"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat(),
            'api_key_count': len(self.api_keys)
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