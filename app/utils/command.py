import re
import socket
import subprocess
import shlex
from typing import Dict, Optional

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent command injection
    """
    # Remove potentially dangerous characters
    return re.sub(r'[;&|<>$()]', '', input_str)

def run_command(command: str) -> str:
    """
    Run a shell command safely and return its output
    """
    # Use shlex.split to properly handle shell arguments
    args = shlex.split(command)
    
    # Run the command with a timeout to prevent hanging
    process = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=60,  # 1 minute timeout
        check=False  # Don't raise an exception on non-zero exit
    )
    
    # Combine stdout and stderr for complete output
    output = process.stdout
    if process.stderr:
        output += "\n" + process.stderr
    
    return output

def run_ping(host: str, count: int = 4) -> str:
    """
    Run ping command against a host
    """
    host = sanitize_input(host)
    # Construct ping command based on count
    command = f"ping -c {count} {host}"
    return run_command(command)

def run_traceroute(host: str, max_hops: int = 30) -> str:
    """
    Run traceroute command against a host
    """
    host = sanitize_input(host)
    # Construct traceroute command
    command = f"traceroute -m {max_hops} {host}"
    return run_command(command)

def run_dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Run DNS lookup using dig command
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type)
    # Construct dig command
    command = f"dig {record_type} {domain} +short"
    return run_command(command)

def run_whois(domain: str) -> str:
    """
    Run WHOIS lookup on a domain
    """
    domain = sanitize_input(domain)
    # Construct whois command
    command = f"whois {domain}"
    return run_command(command)

def run_curl(
    url: str, 
    method: str = "GET", 
    headers: Optional[Dict[str, str]] = None, 
    data: Optional[str] = None, 
    timeout: int = 30
) -> str:
    """
    Run curl command against a URL
    """
    # Prepare command with method and timeout
    command = f"curl -X {method} --max-time {timeout} -sS -i"
    
    # Add headers if provided
    if headers:
        for key, value in headers.items():
            safe_key = sanitize_input(key)
            safe_value = sanitize_input(value)
            command += f" -H '{safe_key}: {safe_value}'"
    
    # Add data if provided
    if data and method != "GET":
        safe_data = sanitize_input(data)
        command += f" -d '{safe_data}'"
    
    # Add URL (must be properly escaped)
    safe_url = sanitize_input(url)
    command += f" '{safe_url}'"
    
    return run_command(command)

def run_port_check(host: str, port: int, timeout: int = 5) -> str:
    """
    Check if a port is open on a host using a socket connection
    """
    host = sanitize_input(host)
    try:
        # Create socket and attempt to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        
        if result == 0:
            return f"Port {port} is open on {host}"
        else:
            return f"Port {port} is closed on {host} (error code: {result})"
    except socket.gaierror:
        return f"Could not resolve hostname: {host}"
    except socket.timeout:
        return f"Connection to {host}:{port} timed out after {timeout} seconds"
    except Exception as e:
        return f"Error checking port {port} on {host}: {str(e)}"
    finally:
        sock.close()
