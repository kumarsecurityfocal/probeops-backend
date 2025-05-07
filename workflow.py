#!/usr/bin/env python3
"""
Workflow utility for starting the FastAPI application with uvicorn.
"""
import os
import sys
import subprocess

def start_application():
    """Start the FastAPI application with uvicorn."""
    # Use uvicorn to run the application
    subprocess.run([
        "uvicorn", 
        "main:app", 
        "--host", "0.0.0.0", 
        "--port", "5000", 
        "--reload"
    ], check=True)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "start":
            start_application()
    else:
        print("Usage: python workflow.py start")
        sys.exit(1)