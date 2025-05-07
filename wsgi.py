"""
WSGI Configuration

This file provides a custom Uvicorn worker class for Gunicorn
to properly handle our FastAPI ASGI application.

Usage: gunicorn -w 4 -k wsgi:AppUvicornWorker app:app
"""
from uvicorn.workers import UvicornWorker

class AppUvicornWorker(UvicornWorker):
    """
    Custom Uvicorn worker class that enables the use of FastAPI with gunicorn.
    
    Usage: gunicorn -w 4 -k wsgi:AppUvicornWorker app:app
    """
    CONFIG_KWARGS = {
        "log_level": "info",
        "lifespan": "on"
    }