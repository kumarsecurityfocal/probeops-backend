from uvicorn.workers import UvicornWorker

class AppUvicornWorker(UvicornWorker):
    """
    Custom Uvicorn worker class that enables the use of FastAPI with gunicorn.
    
    Usage: gunicorn -w 4 -k wsgi:AppUvicornWorker main:app
    """
    CONFIG_KWARGS = {
        "log_level": "info",
        "lifespan": "on"
    }