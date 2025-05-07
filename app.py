"""
ProbeOps API - Flask-based Network Diagnostics API with JWT Authentication and API Keys
"""
import os
import logging
from datetime import datetime

from flask import Flask, jsonify, request, redirect, url_for
from flask_cors import CORS

from app_config import create_app
from models import db, User, ApiKey, ProbeJob
from auth import current_user

# Import route blueprints
from routes_user import bp as user_bp
from routes_apikey import bp as apikey_bp
from routes_probe import bp as probe_bp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create the Flask application
app = create_app()

# Register blueprints
app.register_blueprint(user_bp)
app.register_blueprint(apikey_bp)
app.register_blueprint(probe_bp)


@app.route('/')
def root():
    """API root endpoint"""
    return jsonify({
        "name": "ProbeOps API",
        "version": "1.0.0",
        "status": "online",
        "authenticated": current_user is not None,
        "user": current_user.username if current_user else None,
        "endpoints": {
            "auth": [
                "/users/register",
                "/users/login",
                "/users/me"
            ],
            "api_keys": [
                "/apikeys"
            ],
            "probes": [
                "/probes/ping",
                "/probes/traceroute",
                "/probes/dns",
                "/probes/whois",
                "/probes/history"
            ]
        }
    })


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Not found",
        "message": "The requested resource was not found."
    }), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}")
    return jsonify({
        "error": "Server error",
        "message": "An internal server error occurred."
    }), 500


# Admin routes for server management
@app.route('/admin/server_status')
def server_status():
    """Admin endpoint to check the server status"""
    from subprocess import run, PIPE
    
    def run_command(cmd):
        result = run(cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True)
        return result.stdout
    
    memory_info = run_command("free -h")
    disk_info = run_command("df -h")
    process_info = run_command("ps aux | grep python")
    database_info = {
        "users": User.query.count(),
        "api_keys": ApiKey.query.count(),
        "probe_jobs": ProbeJob.query.count()
    }
    
    return jsonify({
        "status": "running",
        "memory": memory_info,
        "disk": disk_info,
        "processes": process_info,
        "database": database_info
    })


# Required for gunicorn
application = app

if __name__ == "__main__":
    # For direct execution (not via gunicorn)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)