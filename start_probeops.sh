#!/bin/bash
# Start the ProbeOps FastAPI application with gunicorn using the UvicornWorker

# Make sure the necessary Python packages are installed
echo "Starting ProbeOps API..."

# Run with gunicorn using the Uvicorn worker for ASGI
exec gunicorn -c gunicorn_config.py main:app