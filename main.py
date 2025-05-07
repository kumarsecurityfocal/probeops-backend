"""
Main entry point for the ProbeOps API.
This file imports the Flask server for use with gunicorn.
"""
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our application from the flask_server.py file
from flask_server import app, application

# For direct execution
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)