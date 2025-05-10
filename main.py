"""
Main entry point for the ProbeOps API.
This file imports the Flask app for use with gunicorn.
"""
from flask_migrate import Migrate
from probeops.app import create_app, db

app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)