"""
Gunicorn configuration file for the FastAPI application.
This configures gunicorn to use the uvicorn worker class which can handle ASGI applications.
"""
import multiprocessing

# Define the worker class to use
worker_class = "uvicorn.workers.UvicornWorker"

# Number of workers
workers = multiprocessing.cpu_count() * 2 + 1
if workers > 8:
    workers = 8

# Bind to this socket
bind = "0.0.0.0:5000"

# Other settings
timeout = 120
keepalive = 5
worker_connections = 1000
accesslog = "-"
errorlog = "-"
loglevel = "info"
reload = True