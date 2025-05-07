"""
Main entry point for the ProbeOps API.
This file imports the Flask app for use with gunicorn.
"""
from flask_app import app

# Required for gunicorn
application = app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)