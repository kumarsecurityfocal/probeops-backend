"""
Simple script to start the FastAPI application using uvicorn directly.
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "server:app", 
        host="0.0.0.0", 
        port=5000, 
        reload=True, 
        log_level="info"
    )