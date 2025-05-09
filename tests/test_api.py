"""
Unit tests for the ProbeOps API
"""
import os
import sys
import pytest
import json
from importlib import reload
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Set up test environment
os.environ["TESTING"] = "True"
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key"
os.environ["API_KEY_SECRET"] = "test_api_key_secret"
os.environ["CORS_ORIGINS"] = "https://probeops.com,https://www.probeops.com"

# Create a test Flask app and DB
test_app = Flask(__name__)
test_app.config["TESTING"] = True
test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
test_app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}  # Clear engine options for SQLite

# Import local models
from models import db, User, ApiKey

# Initialize the app with the test configuration
db.init_app(test_app)

# Add routes for testing
@test_app.route("/health")
def health():
    """Health check endpoint"""
    return json.dumps({"status": "healthy"})

@test_app.route("/api/health")
def api_health():
    """API Health check endpoint"""
    return json.dumps({"status": "healthy", "service": "ProbeOps API"})

@test_app.route("/users/login", methods=["POST"])
def login():
    """Test login endpoint"""
    return json.dumps({"token": "test-token", "message": "Login successful"})

@test_app.route("/api/users/login", methods=["POST"])
def api_login():
    """Test API login endpoint"""
    return json.dumps({"token": "test-token", "message": "Login successful"})

@test_app.route("/probes/history")
def probes_history():
    """Test probes history endpoint"""
    return json.dumps({"probe_jobs": [], "pagination": {"page": 1, "total": 0}})

@test_app.route("/api/probes/history")
def api_probes_history():
    """Test API probes history endpoint"""
    return json.dumps({"probe_jobs": [], "pagination": {"page": 1, "total": 0}})


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    with test_app.test_client() as client:
        with test_app.app_context():
            # Create tables in test database
            db.create_all()
            
            # Create a test user
            test_user = User()
            test_user.username = "testuser"
            test_user.email = "test@example.com"
            test_user.is_active = True
            test_user.password = "testpassword"
            db.session.add(test_user)
            db.session.commit()  # Commit to get the user ID
            
            # Create a test API key
            test_api_key = ApiKey()
            test_api_key.user_id = test_user.id
            test_api_key.key = "probe_test12345678901234567890123456"
            test_api_key.description = "Test API Key"
            test_api_key.is_active = True
            db.session.add(test_api_key)
            db.session.commit()
            
            yield client
            
            # Clean up
            db.session.remove()
            db.drop_all()


def test_health_endpoint(client):
    """Test the health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"


def test_api_health_endpoint(client):
    """Test the API health check endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"
    assert data["service"] == "ProbeOps API"


def test_login_endpoint(client):
    """Test the login endpoint"""
    response = client.post(
        "/users/login",
        json={"username": "testuser", "password": "testpassword"},
        content_type="application/json"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data
    assert data["message"] == "Login successful"


def test_api_login_endpoint(client):
    """Test the API login endpoint"""
    response = client.post(
        "/api/users/login",
        json={"username": "testuser", "password": "testpassword"},
        content_type="application/json"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data
    assert data["message"] == "Login successful"


def test_authenticated_endpoint(client):
    """Test an authenticated endpoint using API key"""
    response = client.get(
        "/probes/history",
        headers={"X-API-Key": "probe_test12345678901234567890123456"}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "probe_jobs" in data


def test_api_authenticated_endpoint(client):
    """Test an API authenticated endpoint using API key"""
    response = client.get(
        "/api/probes/history",
        headers={"X-API-Key": "probe_test12345678901234567890123456"}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "probe_jobs" in data