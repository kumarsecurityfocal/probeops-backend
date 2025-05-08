#!/bin/bash

# Wait for the database to be ready
echo "Waiting for PostgreSQL to be ready..."
while ! nc -z db 5432; do
  sleep 0.5
done
echo "PostgreSQL is ready!"

# Load environment variables from .env if it exists
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Run database migrations or initialization
echo "Setting up database tables..."
python -c "from flask_server import app, db; app.app_context().push(); db.create_all()"

# Start the application
echo "Starting ProbeOps API server..."
exec gunicorn --bind 0.0.0.0:5000 \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --access-logfile - \
    --error-logfile - \
    "main:app"