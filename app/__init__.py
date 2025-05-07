from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.routes import router as auth_router
from app.probes.routes import router as probes_router
from app.db.session import create_tables

# Create FastAPI app
app = FastAPI(
    title="ProbeOps API",
    description="Network diagnostics API with JWT authentication",
    version="1.0.0",
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

# Create database tables
create_tables()

# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to ProbeOps API", "status": "online"}
