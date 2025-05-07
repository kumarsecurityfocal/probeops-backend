#!/usr/bin/env python
"""
FastAPI application starter for Replit workflow.
This script correctly runs the FastAPI application using uvicorn.
"""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting ProbeOps API on port {port}...")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=port,
        reload=True,
    )