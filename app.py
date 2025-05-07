"""
Main application entry point for FastAPI.
For running with uvicorn, use: 
$ uvicorn app:app --host 0.0.0.0 --port 5000 --reload
"""
from app import app as application

# Create an alias to app variable for compatibility with different servers
app = application

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)