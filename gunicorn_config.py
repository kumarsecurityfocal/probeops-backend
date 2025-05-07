"""
Gunicorn configuration file for the FastAPI application.
This configures gunicorn to use the uvicorn worker class which can handle ASGI applications.
"""
# Server socket settings
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 120
keepalive = 5

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = None

# Server hooks
def on_starting(server):
    print("Starting the ProbeOps API server...")

def on_reload(server):
    print("Reloading the ProbeOps API server...")