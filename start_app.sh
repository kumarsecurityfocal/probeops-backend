#!/bin/bash
# Start the FastAPI application with uvicorn directly

echo "Starting ProbeOps API..."
python -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload