import re
import socket
import subprocess
import shlex
from typing import Dict, Optional

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent command injection
    """
    # Remove shell metacharacters
    return re.sub(r'[;&|`$\\><\n]', '', input_str)

def run_command(command: str) -> str:
    """
    Run a shell command safely and return its output
    """
    try:
        # Execute command with shell=False for security
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=60,  # Add timeout for safety
            check=False
        )
        
        # Combine stdout and stderr
        output = result.stdout
        if result.stderr:
            output += f"\nERROR: {result.stderr}"
            
        return output.strip()
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out after 60 seconds"
    except Exception as e:
        return f"ERROR: Failed to execute command: {str(e)}"

def run_ping(host: str, count: int = 4) -> str:
    """
    Run ping command against a host
    """
    sanitized_host = sanitize_input(host)
    sanitized_count = min(max(1, count), 20)  # Limit count between 1 and 20
    
    command = f"ping -c {sanitized_count} {sanitized_host}"
    return run_command(command)

def run_traceroute(host: str, max_hops: int = 30) -> str:
    """
    Run traceroute command against a host
    """
    sanitized_host = sanitize_input(host)
    sanitized_max_hops = min(max(1, max_hops), 64)  # Limit max_hops between 1 and 64
    
    command = f"traceroute -m {sanitized_max_hops} {sanitized_host}"
    return run_command(command)

def run_dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Run DNS lookup using dig command
    """
    sanitized_domain = sanitize_input(domain)
    sanitized_record_type = sanitize_input(record_type).upper()
    
    # Ensure record type is valid
    valid_types = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
    if sanitized_record_type not in valid_types:
        sanitized_record_type = "A"
    
    command = f"dig {sanitized_record_type} {sanitized_domain} +short"
    result = run_command(command)
    
    # If no result, try with non-short output
    if not result or result.startswith("ERROR"):
        command = f"dig {sanitized_record_type} {sanitized_domain}"
        result = run_command(command)
    
    return result

def run_whois(domain: str) -> str:
    """
    Run WHOIS lookup on a domain
    """
    sanitized_domain = sanitize_input(domain)
    command = f"whois {sanitized_domain}"
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
    sanitized_url = sanitize_input(url)
    sanitized_method = sanitize_input(method).upper()
    sanitized_timeout = min(max(1, timeout), 120)  # Limit timeout between 1 and 120 seconds
    
    # Construct the command
    command = f"curl -X {sanitized_method} -s -v --max-time {sanitized_timeout}"
    
    # Add headers if provided
    if headers:
        for key, value in headers.items():
            sanitized_key = sanitize_input(key)
            sanitized_value = sanitize_input(value)
            command += f" -H '{sanitized_key}: {sanitized_value}'"
    
    # Add data if provided
    if data and sanitized_method in ["POST", "PUT", "PATCH"]:
        sanitized_data = sanitize_input(data)
        command += f" -d '{sanitized_data}'"
    
    # Add URL
    command += f" {sanitized_url}"
    
    return run_command(command)

def run_port_check(host: str, port: int, timeout: int = 5) -> str:
    """
    Check if a port is open on a host using a socket connection
    """
    sanitized_host = sanitize_input(host)
    sanitized_port = min(max(1, port), 65535)  # Limit port between 1 and 65535
    sanitized_timeout = min(max(1, timeout), 30)  # Limit timeout between 1 and 30 seconds
    
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(sanitized_timeout)
        
        # Try to connect
        result = sock.connect_ex((sanitized_host, sanitized_port))
        sock.close()
        
        if result == 0:
            # Use nmap if available for service detection
            service_info = run_command(f"nmap -p {sanitized_port} {sanitized_host}")
            return f"Port {sanitized_port} is OPEN on {sanitized_host}\n{service_info}"
        else:
            return f"Port {sanitized_port} is CLOSED on {sanitized_host} (Error: {result})"
    
    except socket.gaierror:
        return f"Error: Hostname {sanitized_host} could not be resolved"
    except socket.error as e:
        return f"Error: Connection to {sanitized_host}:{sanitized_port} failed: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"