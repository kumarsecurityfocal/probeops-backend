#!/bin/bash
# Start script for the FastAPI application using uvicorn directly
echo "Starting FastAPI application with uvicorn..."
exec uvicorn simple_app:app --host 0.0.0.0 --port 5000 --reload