"""
Unit tests for the ProbeOps API
"""
import os
import pytest
import json
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Set up test environment
os.environ["TESTING"] = "True"
os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key"
os.environ["API_KEY_SECRET"] = "test_api_key_secret"
os.environ["CORS_ORIGINS"] = "https://probeops.com,https://www.probeops.com"

# Import the Flask app after setting environment variables
from flask_server import app, db, User, ApiKey


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///:memory:"
    )
    
    with app.test_client() as client:
        with app.app_context():
            # Create tables in test database
            db.create_all()
            
            # Create a test user
            test_user = User(
                username="testuser",
                email="test@example.com",
                is_active=True
            )
            test_user.password = "testpassword"
            db.session.add(test_user)
            
            # Create a test API key
            test_api_key = ApiKey(
                user=test_user,
                key="probe_test12345678901234567890123456",
                description="Test API Key"
            )
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