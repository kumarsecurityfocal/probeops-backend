import os
from typing import Optional

def get_database_url() -> str:
    """Get database URL from environment variables"""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        # Fallback to construct from individual variables
        user = os.environ.get("PGUSER", "postgres")
        password = os.environ.get("PGPASSWORD", "postgres")
        host = os.environ.get("PGHOST", "localhost")
        port = os.environ.get("PGPORT", "5432")
        db = os.environ.get("PGDATABASE", "probeops")
        database_url = f"postgresql://{user}:{password}@{host}:{port}/{db}"
    
    return database_url

def get_jwt_settings() -> dict:
    """Get JWT settings from environment variables"""
    return {
        "secret_key": os.environ.get("JWT_SECRET_KEY", "4f0e1dc2f5ddd8a2a73c5cdfd1f7a10dc48de6a9f37a942e7eb57e5b614e8201"),
        "algorithm": "HS256",
        "access_token_expire_minutes": int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    }

def get_cors_origins() -> list:
    """Get CORS allowed origins from environment variables"""
    origins = os.environ.get("CORS_ORIGINS", "*")
    if origins == "*":
        return ["*"]
    return [origin.strip() for origin in origins.split(",")]

def get_app_settings() -> dict:
    """Get application settings"""
    return {
        "title": "ProbeOps API",
        "description": "Network diagnostics API with JWT authentication",
        "version": "1.0.0",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "openapi_url": "/openapi.json"
    }