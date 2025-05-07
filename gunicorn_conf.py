"""
Gunicorn configuration file for running FastAPI with uvicorn workers
"""

# This is a Gunicorn configuration file that uses Uvicorn workers
# for running a FastAPI application.

bind = "0.0.0.0:5000"
worker_class = "uvicorn.workers.UvicornWorker"
workers = 1  # For development, use 1 worker
reload = True  # Auto-reload on code changes
timeout = 120  # Increased timeout for development
keepalive = 5  # How long to wait for requests on a Keep-Alive connection
errorlog = "-"  # Log to stderr
accesslog = "-"  # Log to stdout
loglevel = "info"