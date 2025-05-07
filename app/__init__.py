from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.auth.routes import router as auth_router
from app.probes.routes import router as probes_router
from app.db.session import create_tables, get_db
from app.config.settings import get_app_settings, get_cors_origins
from sqlalchemy.orm import Session

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup
    print("Starting up ProbeOps API...")
    try:
        print("Creating database tables if they don't exist...")
        create_tables()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
    
    yield
    
    # On shutdown
    print("Shutting down ProbeOps API...")

# Get app settings from config
app_settings = get_app_settings()

# Create FastAPI app
app = FastAPI(
    title=app_settings["title"],
    description=app_settings["description"],
    version=app_settings["version"],
    docs_url=app_settings["docs_url"],
    redoc_url=app_settings["redoc_url"],
    openapi_url=app_settings["openapi_url"],
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
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
    return {
        "message": "Welcome to ProbeOps API", 
        "status": "online",
        "version": app_settings["version"],
        "docs_url": app_settings["docs_url"],
        "redoc_url": app_settings["redoc_url"]
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "OK", "message": "Service is running"}

# Database check endpoint
@app.get("/db-test", tags=["Health"])
async def db_test(db: Session = Depends(get_db)):
    try:
        # Try to execute a simple query
        db.execute("SELECT 1")
        return {"status": "OK", "message": "Database connection successful"}
    except Exception as e:
        return {"status": "ERROR", "message": f"Database connection failed: {str(e)}"}
