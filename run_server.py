#!/usr/bin/env python
"""
Custom workflow runner for the ProbeOps FastAPI application.
This script properly starts the application with uvicorn.
"""
import uvicorn

def main():
    """Run the FastAPI application with Uvicorn"""
    print("Starting ProbeOps API...")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
        log_level="info",
    )

if __name__ == "__main__":
    main()