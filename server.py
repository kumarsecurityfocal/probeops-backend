"""
Independent server starter for FastAPI app.
This script starts a FastAPI application without relying on relative imports.
"""
import os
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# Import SQLAlchemy database connection
from app.db.session import get_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events for the FastAPI application."""
    # On startup events
    print("Starting up FastAPI application...")
    
    # Initialize database tables
    from app.db.session import create_tables
    try:
        print("Creating database tables if they don't exist...")
        create_tables()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
    
    yield
    
    # On shutdown events
    print("Shutting down FastAPI application...")
    # Add any cleanup code here (e.g., closing connections)

# Create the FastAPI application
app = FastAPI(
    title="ProbeOps API",
    description="Network diagnostic API with JWT authentication",
    version="0.1.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic health check endpoint
@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {"status": "OK", "message": "Service is running"}

# Simple hello endpoint
@app.get("/hello")
async def hello():
    """Simple hello world endpoint"""
    return {"message": "Hello, World!"}

# Database test endpoint
@app.get("/db-test")
async def db_test(db: Session = Depends(get_db)):
    """Test database connection"""
    try:
        # Try to execute a simple query
        db.execute("SELECT 1")
        return {"status": "OK", "message": "Database connection successful"}
    except Exception as e:
        return {"status": "ERROR", "message": f"Database connection failed: {str(e)}"}

# Root endpoint
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "ProbeOps API",
        "version": "0.1.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# When this script is run directly
if __name__ == "__main__":
    import uvicorn
    # Start the FastAPI app with Uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=5000, reload=True)