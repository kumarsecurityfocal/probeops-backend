"""
ASGI entry point for our FastAPI application.
This file is used by gunicorn to correctly serve our FastAPI application.
"""
from simple_app import app

# Import for gunicorn
application = app

# For direct uvicorn usage
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("asgi:application", host="0.0.0.0", port=5000, reload=True)