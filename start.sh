#!/bin/bash
# Start script for running the FastAPI application using plain uvicorn
# This avoids ASGI/WSGI compatibility issues

exec uvicorn main:app --host 0.0.0.0 --port 5000 --reload