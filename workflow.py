#!/usr/bin/env python
"""
Workflow utility for starting the FastAPI application with uvicorn.
"""
import os
import uvicorn

def start_application():
    """Start the FastAPI application with uvicorn."""
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        reload=True,
    )