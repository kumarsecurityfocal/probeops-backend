"""
Network probe services for ProbeOps API
"""
import os
import json
import socket
import logging
import subprocess
import re
from datetime import datetime

from probeops.models import ProbeJob
from probeops.app import db
from probeops.services.auth import get_current_user

# Configure logging
logger = logging.getLogger(__name__)


def sanitize_input(input_str):
    """
    Sanitize input to prevent command injection
    """
    # Remove any potentially dangerous characters
    sanitized = re.sub(r'[;&|<>$`\\]', '', input_str)
    # Only allow alphanumeric, dots, dashes, and underscores
    sanitized = re.sub(r'[^a-zA-Z0-9\-_\.]', '', sanitized)
    return sanitized


def run_command(command):
    """
    Run a shell command safely and return its output
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out after 30 seconds"
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return f"Error: {str(e)}"


def run_ping(host, count=4):
    """
    Run ping command against a host
    """
    host = sanitize_input(host)
    try:
        # Use the ping command
        command = ["ping", "-c", str(count), host]
        return run_command(command)
    except Exception as e:
        logger.error(f"Error running ping: {e}")
        return f"Error: {str(e)}"


def run_traceroute(host, max_hops=30):
    """
    Run traceroute command against a host
    """
    host = sanitize_input(host)
    try:
        # Use the traceroute command
        command = ["traceroute", "-m", str(max_hops), host]
        return run_command(command)
    except Exception as e:
        logger.error(f"Error running traceroute: {e}")
        return f"Error: {str(e)}"


def run_dns_lookup(domain, record_type="A"):
    """
    Run DNS lookup using dig command
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type).upper()
    try:
        # Use the dig command
        command = ["dig", f"{record_type}", domain]
        return run_command(command)
    except Exception as e:
        logger.error(f"Error running DNS lookup: {e}")
        return f"Error: {str(e)}"


def run_whois(domain):
    """
    Run WHOIS lookup using whois command
    """
    domain = sanitize_input(domain)
    try:
        # Use the whois command
        command = ["whois", domain]
        return run_command(command)
    except Exception as e:
        logger.error(f"Error running WHOIS lookup: {e}")
        return f"Error: {str(e)}"


def save_probe_job(probe_type, target, parameters, result, success=True):
    """Save probe job to database"""
    user = get_current_user()
    if not user:
        logger.warning("No authenticated user to save probe job")
        return None
    
    try:
        # Create probe job
        probe_job = ProbeJob(
            user_id=user.id,
            probe_type=probe_type,
            target=target,
            parameters=json.dumps(parameters) if parameters else None,
            result=result,
            success=success,
            created_at=datetime.utcnow()
        )
        
        # Save to database
        db.session.add(probe_job)
        db.session.commit()
        
        return probe_job
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving probe job: {e}")
        return None


def format_response(success, probe_type, target, result, job_id=0):
    """
    Format a standardized response for probe operations
    """
    return {
        "success": success,
        "probe_type": probe_type,
        "target": target,
        "result": result,
        "timestamp": datetime.utcnow().isoformat(),
        "job_id": job_id
    }