"""
Main application entry point for ProbeOps FastAPI.
This file initializes and configures the FastAPI application.
"""
import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from typing import Dict, Any

# Import database configuration
from app.db.session import get_db, create_tables
# Import routes
from app.auth.routes import router as auth_router
from app.probes.routes import router as probes_router

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events for the FastAPI application."""
    print("Starting up ProbeOps API...")
    print("Creating database tables if they don't exist...")
    create_tables()
    print("Database tables created successfully.")
    yield
    print("Shutting down ProbeOps API...")

# Create FastAPI application
app = FastAPI(
    title="ProbeOps API",
    description="Network diagnostics and probe operations API",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(probes_router, prefix="/probes", tags=["Probe Operations"])

# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """API root endpoint."""
    return {
        "message": "Welcome to ProbeOps API",
        "documentation": "/docs",
        "version": "1.0.0"
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, Any]:
    """Simple health check endpoint."""
    return {
        "status": "OK",
        "message": "Service is running"
    }

# Database test endpoint
@app.get("/db-test", tags=["Health"])
async def db_test(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Test database connection."""
    try:
        # Just get a connection and verify it works
        db.execute("SELECT 1")
        return {
            "status": "OK",
            "message": "Database connection successful"
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Database connection failed: {str(e)}"
        }

# Run the application directly with uvicorn when this file is executed
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)