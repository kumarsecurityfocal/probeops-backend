#!/usr/bin/env python3
"""
Custom starter script that runs a FastAPI application with Uvicorn directly.
This bypasses the ASGI/WSGI adapter issues with gunicorn.
"""
import os
import uvicorn

def main():
    """Run the FastAPI application with Uvicorn"""
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    # Point to server.py which contains our FastAPI app
    uvicorn.run(
        "server:app", 
        host=host, 
        port=port, 
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()