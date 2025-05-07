"""
Main application entry point.
Import FastAPI application from app module.
"""
from app import app

# When this file is imported by gunicorn or uvicorn, they will use this app object
# For direct execution with python, use the conditional below

if __name__ == "__main__":
    # For direct execution
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
