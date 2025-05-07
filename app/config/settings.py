import os
from typing import Optional

# PostgreSQL configuration
def get_database_url() -> str:
    """Get database URL from environment variables"""
    # Try to get DATABASE_URL directly
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url
    
    # Otherwise, construct from individual components
    db_user = os.getenv("PGUSER", "postgres")
    db_password = os.getenv("PGPASSWORD", "postgres")
    db_host = os.getenv("PGHOST", "localhost")
    db_port = os.getenv("PGPORT", "5432")
    db_name = os.getenv("PGDATABASE", "probeops")
    
    return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

# API Settings
API_V1_PREFIX = "/api/v1"
PROJECT_NAME = "ProbeOps"
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

# CORS settings
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# Security settings - use environment variable for production
# JWT Token settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "4f0e1dc2f5ddd8a2a73c5cdfd1f7a10dc48de6a9f37a942e7eb57e5b614e8201")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
