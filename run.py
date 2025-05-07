#!/usr/bin/env python
"""
Custom starter script that runs a FastAPI application with Uvicorn directly.
This bypasses the ASGI/WSGI adapter issues with gunicorn.
"""
import os
import uvicorn

def main():
    """Run the FastAPI application with Uvicorn"""
    port = int(os.environ.get("PORT", 5001))  # Use a different port than gunicorn
    print(f"Starting FastAPI application on port {port}...")
    uvicorn.run(
        "simple_app:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        reload_excludes=[".*", "*.pyc", "*.log"],
        log_level="info",
    )

if __name__ == "__main__":
    main()