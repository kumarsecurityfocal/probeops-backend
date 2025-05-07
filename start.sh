#!/bin/bash
# Start the FastAPI application with gunicorn and the appropriate worker class

echo "Starting ProbeOps API..."
echo "Using Gunicorn with Uvicorn worker for ASGI application"

exec gunicorn -k wsgi:AppUvicornWorker --bind 0.0.0.0:5000 --reload app:app