"""
A simple standalone FastAPI application with minimal requirements.
This avoids the complex modular structure and focuses on demonstrating basic functionality.
"""
import os
from typing import Dict, Any

import fastapi
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Create FastAPI app
app = FastAPI(
    title="ProbeOps API",
    description="Network diagnostics API with JWT authentication",
    version="0.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./test.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Health check endpoint
@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Simple health check endpoint."""
    return {
        "status": "OK",
        "message": "Service is running",
        "fastapi_version": fastapi.__version__
    }

# Hello endpoint
@app.get("/hello")
async def hello() -> Dict[str, str]:
    """Simple hello world endpoint."""
    return {"message": "Hello, World!"}

# Database test endpoint
@app.get("/db-test")
async def db_test(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Test database connection."""
    try:
        # Try to execute a simple query
        result = db.execute(text("SELECT 1")).scalar()
        return {
            "status": "OK", 
            "message": "Database connection successful",
            "result": result
        }
    except Exception as e:
        return {
            "status": "ERROR", 
            "message": f"Database connection failed: {str(e)}",
            "database_url": DATABASE_URL.replace(os.environ.get("PGPASSWORD", ""), "********")
        }

# Root endpoint
@app.get("/")
async def root() -> Dict[str, Any]:
    """API root endpoint."""
    return {
        "name": "ProbeOps API",
        "version": "0.1.0",
        "endpoints": [
            {"path": "/", "description": "Root endpoint - API information"},
            {"path": "/health", "description": "Health check endpoint"},
            {"path": "/hello", "description": "Hello world test endpoint"},
            {"path": "/db-test", "description": "Database connection test endpoint"},
            {"path": "/docs", "description": "API documentation (Swagger UI)"},
            {"path": "/redoc", "description": "API documentation (ReDoc)"}
        ]
    }

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("simple_app:app", host="0.0.0.0", port=5000, reload=True)