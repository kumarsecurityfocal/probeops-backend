"""
Independent server starter for FastAPI app.
This script starts a FastAPI application without relying on relative imports.
"""
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Set the Python path to include the current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the routers
from app.auth.routes import router as auth_router
from app.probes.routes import router as probes_router
from app.db.session import create_tables

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events for the FastAPI application."""
    # Create tables on startup
    create_tables()
    yield
    # Cleanup on shutdown if needed
    pass

# Create FastAPI app
app = FastAPI(
    title="ProbeOps API",
    description="Network diagnostics API with JWT authentication",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(probes_router, prefix="/probes", tags=["Network Probes"])

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to ProbeOps API", "status": "online"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=5000, reload=True)