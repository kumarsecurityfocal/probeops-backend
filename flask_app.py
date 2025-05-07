"""
Flask implementation of the ProbeOps API
This provides a direct Flask-based implementation that works well in the Replit environment.
"""
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

from flask import Flask, jsonify, request, Response, render_template, redirect, url_for, session, flash

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "probeops_development_secret")

# Network probe functions
def run_command(command: str) -> str:
    """
    Run a shell command safely and return its output
    """
    try:
        logger.info(f"Running command: {command}")
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=30
        )
        logger.debug(f"Command output: {result.stdout}")
        if result.returncode != 0:
            logger.error(f"Command failed with code {result.returncode}: {result.stderr}")
            return f"Error (code {result.returncode}): {result.stderr}"
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return "Error: Command timed out"
    except Exception as e:
        logger.exception(f"Error running command: {str(e)}")
        return f"Error: {str(e)}"

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent command injection
    """
    # Remove potentially dangerous characters
    sanitized = ''.join(c for c in input_str if c.isalnum() or c in '.-_:/')
    return sanitized

def run_ping(host: str, count: int = 4) -> str:
    """
    Run ping command against a host
    """
    host = sanitize_input(host)
    return run_command(f"ping -c {count} {host}")

def run_traceroute(host: str, max_hops: int = 30) -> str:
    """
    Run traceroute command against a host
    """
    host = sanitize_input(host)
    return run_command(f"traceroute -m {max_hops} {host}")

def run_dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Run DNS lookup using dig command
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type)
    return run_command(f"dig {record_type} {domain}")

def run_whois(domain: str) -> str:
    """
    Run WHOIS lookup on a domain
    """
    domain = sanitize_input(domain)
    return run_command(f"whois {domain}")

def format_response(
    success: bool, 
    probe_type: str, 
    target: str, 
    result: str,
    job_id: int = 0
) -> Dict[str, Any]:
    """
    Format a standardized response for probe operations
    """
    return {
        "success": success,
        "probe_type": probe_type,
        "target": target,
        "result": result,
        "job_id": job_id,
        "timestamp": datetime.utcnow().isoformat()
    }

# Routes
@app.route('/')
def root():
    """API root endpoint"""
    return jsonify({
        "name": "ProbeOps API",
        "version": "1.0.0",
        "status": "online",
        "endpoints": [
            "/health",
            "/probes/ping",
            "/probes/traceroute",
            "/probes/dns",
            "/probes/whois"
        ]
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/probes/ping', methods=['GET', 'POST'])
def ping_probe():
    """Run ping on a target host"""
    if request.method == 'POST':
        data = request.json or {}
        host = data.get('host')
        count = data.get('count', 4)
    else:
        host = request.args.get('host')
        count = int(request.args.get('count', 4))
    
    if not host:
        return jsonify({"error": "Missing required parameter: host"}), 400
    
    try:
        result = run_ping(host, count)
        return jsonify(format_response(True, "ping", host, result))
    except Exception as e:
        logger.exception(f"Error in ping probe: {str(e)}")
        return jsonify(format_response(False, "ping", host, f"Error: {str(e)}")), 500

@app.route('/probes/traceroute', methods=['GET', 'POST'])
def traceroute_probe():
    """Run traceroute on a target host"""
    if request.method == 'POST':
        data = request.json or {}
        host = data.get('host')
        max_hops = data.get('max_hops', 30)
    else:
        host = request.args.get('host')
        max_hops = int(request.args.get('max_hops', 30))
    
    if not host:
        return jsonify({"error": "Missing required parameter: host"}), 400
    
    try:
        result = run_traceroute(host, max_hops)
        return jsonify(format_response(True, "traceroute", host, result))
    except Exception as e:
        logger.exception(f"Error in traceroute probe: {str(e)}")
        return jsonify(format_response(False, "traceroute", host, f"Error: {str(e)}")), 500

@app.route('/probes/dns', methods=['GET', 'POST'])
def dns_probe():
    """Run DNS lookup on a domain"""
    if request.method == 'POST':
        data = request.json or {}
        domain = data.get('domain')
        record_type = data.get('record_type', 'A')
    else:
        domain = request.args.get('domain')
        record_type = request.args.get('record_type', 'A')
    
    if not domain:
        return jsonify({"error": "Missing required parameter: domain"}), 400
    
    try:
        result = run_dns_lookup(domain, record_type)
        return jsonify(format_response(True, "dns", domain, result))
    except Exception as e:
        logger.exception(f"Error in DNS probe: {str(e)}")
        return jsonify(format_response(False, "dns", domain, f"Error: {str(e)}")), 500

@app.route('/probes/whois', methods=['GET', 'POST'])
def whois_probe():
    """Run WHOIS lookup on a domain"""
    if request.method == 'POST':
        data = request.json or {}
        domain = data.get('domain')
    else:
        domain = request.args.get('domain')
    
    if not domain:
        return jsonify({"error": "Missing required parameter: domain"}), 400
    
    try:
        result = run_whois(domain)
        return jsonify(format_response(True, "whois", domain, result))
    except Exception as e:
        logger.exception(f"Error in WHOIS probe: {str(e)}")
        return jsonify(format_response(False, "whois", domain, f"Error: {str(e)}")), 500

# Admin routes for server management
@app.route('/admin/server_status')
def server_status():
    """Admin endpoint to check the server status"""
    memory_info = run_command("free -h")
    disk_info = run_command("df -h")
    process_info = run_command("ps aux | grep python")
    
    return jsonify({
        "status": "running",
        "memory": memory_info,
        "disk": disk_info,
        "processes": process_info
    })

# Required for gunicorn
application = app

if __name__ == "__main__":
    # For direct execution (not via gunicorn)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)