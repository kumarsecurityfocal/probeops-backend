"""
Network probe services for ProbeOps API
"""
import os
import json
import socket
import logging
import subprocess
import re
import time
import platform
import struct
import dns.resolver
import io
import ipwhois
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
    Run ping using Python's socket module (no external commands)
    """
    host = sanitize_input(host)
    output = io.StringIO()
    
    try:
        # Resolve hostname to IP
        output.write(f"PING {host}\n")
        try:
            ip_addr = socket.gethostbyname(host)
            output.write(f"Resolved to IP: {ip_addr}\n\n")
        except socket.gaierror:
            output.write(f"Could not resolve hostname: {host}\n")
            return output.getvalue()
        
        # Create socket for ICMP
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.settimeout(1)
        
        # Statistics
        packet_sent = 0
        packet_received = 0
        total_time = 0
        min_time = float('inf')
        max_time = 0
        
        # Send ping requests
        for seq in range(count):
            try:
                # Create ICMP Echo Request
                checksum = 0
                id_num = os.getpid() & 0xFFFF
                header = struct.pack('!BBHHH', 8, 0, checksum, id_num, seq)
                data = b'ProbeOpsAPI'
                
                # Calculate checksum
                my_checksum = 0
                for i in range(0, len(header) + len(data), 2):
                    if i + 1 < len(header) + len(data):
                        my_checksum += (header + data)[i] + ((header + data)[i + 1] << 8)
                    else:
                        my_checksum += (header + data)[i]
                my_checksum = (my_checksum >> 16) + (my_checksum & 0xffff)
                my_checksum += my_checksum >> 16
                my_checksum = ~my_checksum & 0xffff
                
                # Update header with calculated checksum
                header = struct.pack('!BBHHH', 8, 0, socket.htons(my_checksum), id_num, seq)
                
                # Send packet
                start_time = time.time()
                icmp_socket.sendto(header + data, (ip_addr, 0))
                packet_sent += 1
                
                # Receive response
                resp_data, addr = icmp_socket.recvfrom(1024)
                end_time = time.time()
                elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                # Track statistics
                packet_received += 1
                total_time += elapsed_time
                min_time = min(min_time, elapsed_time)
                max_time = max(max_time, elapsed_time)
                
                output.write(f"64 bytes from {addr[0]}: icmp_seq={seq} time={elapsed_time:.2f} ms\n")
                
                # Add a small delay between pings
                time.sleep(0.2)
                
            except socket.timeout:
                output.write(f"Request timeout for icmp_seq {seq}\n")
            except Exception as e:
                output.write(f"Error during ping sequence {seq}: {str(e)}\n")
        
        # Close socket
        icmp_socket.close()
        
        # Print statistics
        if packet_received > 0:
            avg_time = total_time / packet_received
            loss_percent = ((packet_sent - packet_received) / packet_sent) * 100
            
            output.write(f"\n--- {host} ping statistics ---\n")
            output.write(f"{packet_sent} packets transmitted, {packet_received} received, ")
            output.write(f"{loss_percent:.1f}% packet loss\n")
            output.write(f"rtt min/avg/max = {min_time:.3f}/{avg_time:.3f}/{max_time:.3f} ms\n")
        else:
            output.write(f"\n--- {host} ping statistics ---\n")
            output.write(f"{packet_sent} packets transmitted, 0 received, 100% packet loss\n")
        
        return output.getvalue()
        
    except PermissionError:
        # Fallback for environments where raw sockets are not allowed
        output.write("Python ICMP ping requires root privileges. Using simulated ping.\n\n")
        
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(host)
            output.write(f"Resolved {host} to {resolved_ip}\n")
        except socket.gaierror:
            output.write(f"Could not resolve hostname: {host}\n")
            return output.getvalue()
        
        # Simulate ping with TCP connection to port 80
        packet_sent = 0
        packet_received = 0
        total_time = 0
        min_time = float('inf')
        max_time = 0
        
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
                start_time = time.time()
                packet_sent += 1
                
                # Try to connect to port 80
                s.connect((resolved_ip, 80))
                
                end_time = time.time()
                s.close()
                
                elapsed_time = (end_time - start_time) * 1000
                packet_received += 1
                total_time += elapsed_time
                min_time = min(min_time, elapsed_time)
                max_time = max(max_time, elapsed_time)
                
                output.write(f"TCP conn to {resolved_ip}:80: seq={i} time={elapsed_time:.2f} ms\n")
                time.sleep(0.2)
                
            except (socket.timeout, ConnectionRefusedError):
                output.write(f"Connection to {resolved_ip}:80 timed out: seq={i}\n")
            except Exception as e:
                output.write(f"Error: {str(e)}\n")
        
        # Print statistics
        if packet_received > 0:
            avg_time = total_time / packet_received
            loss_percent = ((packet_sent - packet_received) / packet_sent) * 100
            
            output.write(f"\n--- {host} TCP ping statistics ---\n")
            output.write(f"{packet_sent} packets transmitted, {packet_received} received, ")
            output.write(f"{loss_percent:.1f}% packet loss\n")
            output.write(f"rtt min/avg/max = {min_time:.3f}/{avg_time:.3f}/{max_time:.3f} ms\n")
        else:
            output.write(f"\n--- {host} TCP ping statistics ---\n")
            output.write(f"{packet_sent} packets transmitted, 0 received, 100% packet loss\n")
        
        return output.getvalue()
        
    except Exception as e:
        return f"Error running ping: {str(e)}"


def run_traceroute(host, max_hops=30):
    """
    Run traceroute using Python's socket module
    """
    host = sanitize_input(host)
    output = io.StringIO()
    output.write(f"traceroute to {host}, {max_hops} hops max\n")
    
    try:
        # Resolve the destination host
        try:
            dest_addr = socket.gethostbyname(host)
        except socket.gaierror:
            return f"Could not resolve hostname: {host}"
        
        output.write(f"Tracing route to {host} [{dest_addr}]\n")
        
        # Create a UDP socket for the traceroute
        for ttl in range(1, max_hops + 1):
            # Format the output line
            output.write(f"{ttl:2d} ")
            
            # Send 3 packets per hop
            for probe in range(3):
                try:
                    # Create a socket with the specified TTL
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    s.settimeout(1)
                    
                    # Bind to an ephemeral port
                    s.bind(('', 0))
                    
                    # Record the start time
                    start_time = time.time()
                    
                    # Send a UDP packet to an unlikely port
                    port = 33434 + ttl
                    s.sendto(b'', (dest_addr, port))
                    
                    # Create a raw socket to receive the ICMP response
                    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    recv_socket.settimeout(1)
                    recv_socket.bind(('', 0))
                    
                    # Receive the ICMP response
                    data, addr = recv_socket.recvfrom(1024)
                    end_time = time.time()
                    
                    # Calculate the round-trip time
                    elapsed_time = (end_time - start_time) * 1000
                    
                    # Get the hostname of the responding host
                    try:
                        host_name = socket.gethostbyaddr(addr[0])[0]
                    except socket.herror:
                        host_name = addr[0]
                    
                    # Add the round-trip time to the output
                    output.write(f"{addr[0]} ({host_name}) {elapsed_time:.3f} ms  ")
                    
                    # Close the sockets
                    s.close()
                    recv_socket.close()
                    
                    # If we've reached the destination, we're done
                    if addr[0] == dest_addr:
                        output.write("\nTrace complete.\n")
                        return output.getvalue()
                        
                except socket.timeout:
                    output.write("* ")
                except PermissionError:
                    output.write("Permission error. Requires root privileges. ")
                    return output.getvalue()
                except Exception as e:
                    output.write(f"Error: {str(e)} ")
                finally:
                    try:
                        s.close()
                    except:
                        pass
                    try:
                        recv_socket.close()
                    except:
                        pass
            
            output.write("\n")
        
        output.write("\nTrace complete.\n")
        return output.getvalue()
    
    except PermissionError:
        # Fallback for environments where raw sockets are not allowed
        output.write("Python traceroute requires root privileges. Using simple TCP probe simulation.\n\n")
        
        try:
            # Resolve the destination host
            try:
                dest_addr = socket.gethostbyname(host)
            except socket.gaierror:
                return f"Could not resolve hostname: {host}"
            
            output.write(f"Tracing route to {host} [{dest_addr}] (limited functionality)\n")
            
            # This is a very simple simulation and not an actual traceroute
            for ttl in range(1, min(5, max_hops) + 1):
                output.write(f"{ttl:2d} ")
                
                try:
                    # Create a socket with a very short timeout
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1 * ttl)  # Increase timeout with TTL to simulate
                    
                    # Try to connect to the destination
                    start_time = time.time()
                    result = s.connect_ex((dest_addr, 80))
                    end_time = time.time()
                    
                    elapsed_time = (end_time - start_time) * 1000
                    
                    if result == 0:
                        output.write(f"{dest_addr} (TCP connected) {elapsed_time:.3f} ms\n")
                        s.close()
                        break
                    else:
                        output.write(f"Hop {ttl}: No response (TCP simulation)\n")
                    
                    s.close()
                    
                except Exception as e:
                    output.write(f"Error: {str(e)}\n")
            
            output.write("\nLimited trace simulation complete.\n")
            output.write("This is not a true traceroute but a simplified simulation.\n")
            return output.getvalue()
            
        except Exception as e:
            return f"Error in traceroute simulation: {str(e)}"
    
    except Exception as e:
        return f"Error running traceroute: {str(e)}"


def run_dns_lookup(domain, record_type="A"):
    """
    Run DNS lookup using Python's dns.resolver module
    """
    domain = sanitize_input(domain)
    record_type = sanitize_input(record_type).upper()
    output = io.StringIO()
    
    try:
        output.write(f";; QUESTION SECTION:\n;{domain}.\t\tIN\t{record_type}\n\n")
        output.write(f";; ANSWER SECTION:\n")
        
        # Verify the record type is supported
        valid_types = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
        if record_type not in valid_types:
            record_type = "A"  # Default to A record if invalid
        
        # Perform the DNS query
        answers = dns.resolver.resolve(domain, record_type)
        
        # Process the answers
        for rdata in answers:
            if record_type == "MX":
                output.write(f"{domain}.\t\tIN\t{record_type}\t{rdata.preference} {rdata.exchange}\n")
            elif record_type == "SOA":
                output.write(f"{domain}.\t\tIN\t{record_type}\t{rdata.mname} {rdata.rname} (\n")
                output.write(f"\t\t\t\t\t{rdata.serial}\t; serial\n")
                output.write(f"\t\t\t\t\t{rdata.refresh}\t; refresh\n")
                output.write(f"\t\t\t\t\t{rdata.retry}\t; retry\n")
                output.write(f"\t\t\t\t\t{rdata.expire}\t; expire\n")
                output.write(f"\t\t\t\t\t{rdata.minimum})\t; minimum\n")
            else:
                output.write(f"{domain}.\t\tIN\t{record_type}\t{rdata}\n")
        
        output.write(f"\n;; Query time: {answers.response.time * 1000:.0f} msec\n")
        output.write(f";; SERVER: {answers.nameserver}#{answers.nameserver_port}\n")
        output.write(f";; WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n")
        
        return output.getvalue()
    
    except dns.resolver.NoAnswer:
        output.write(f"No answer for {domain} ({record_type})\n")
        return output.getvalue()
    except dns.resolver.NXDOMAIN:
        output.write(f"Domain {domain} does not exist\n")
        return output.getvalue()
    except dns.exception.Timeout:
        output.write(f"Query for {domain} timed out\n")
        return output.getvalue()
    except Exception as e:
        return f"Error running DNS lookup: {str(e)}"


def run_whois(domain):
    """
    Run WHOIS lookup using Python ipwhois library
    """
    domain = sanitize_input(domain)
    output = io.StringIO()
    
    try:
        # First try to resolve the domain
        try:
            ip = socket.gethostbyname(domain)
            is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) is not None
        except socket.gaierror:
            output.write(f"Error: Could not resolve domain {domain}\n")
            return output.getvalue()
        
        # Handle different lookup types based on whether input is IP or domain
        if is_ip or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            # This is an IP address - use RDAP
            try:
                obj = ipwhois.IPWhois(ip)
                results = obj.lookup_rdap(depth=1)
                
                output.write(f"WHOIS lookup for IP: {ip}\n\n")
                output.write(f"# RDAP data\n")
                
                # Process network information
                if 'network' in results:
                    output.write(f"Network:\n")
                    net = results['network']
                    for k, v in net.items():
                        if v and k not in ['links', 'notices']:
                            output.write(f"  {k}: {v}\n")
                    output.write("\n")
                
                # Process entities information
                if 'entities' in results and results['entities']:
                    output.write(f"Entities:\n")
                    for entity in results['entities']:
                        output.write(f"  {entity}\n")
                    output.write("\n")
                
                # Process objects information
                if 'objects' in results and results['objects']:
                    output.write(f"Objects:\n")
                    for obj_name, obj_data in results['objects'].items():
                        output.write(f"  {obj_name}:\n")
                        
                        if 'contact' in obj_data and obj_data['contact']:
                            output.write(f"    Contact Information:\n")
                            for k, v in obj_data['contact'].items():
                                if v:
                                    output.write(f"      {k}: {v}\n")
                        
                        if 'roles' in obj_data and obj_data['roles']:
                            output.write(f"    Roles: {', '.join(obj_data['roles'])}\n")
                        
                        output.write("\n")
            
            except Exception as e:
                output.write(f"Error in RDAP lookup: {str(e)}\n\n")
                
                # Simplified fallback
                output.write("Simplified IP information:\n")
                output.write(f"IP: {ip}\n")
                output.write(f"Domain: {domain}\n")
                
                try:
                    hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
                    output.write(f"Hostname: {hostname}\n")
                    if aliaslist:
                        output.write(f"Aliases: {', '.join(aliaslist)}\n")
                except socket.herror:
                    output.write("Reverse DNS: No hostname found\n")
        
        else:
            # This is a domain name
            output.write(f"WHOIS lookup for domain: {domain}\n\n")
            output.write("Domain Information:\n")
            output.write(f"  Domain: {domain}\n")
            output.write(f"  IP Address: {ip}\n")
            
            # Get basic DNS information
            try:
                output.write("\nDNS Information:\n")
                
                # Get A records
                try:
                    a_records = dns.resolver.resolve(domain, 'A')
                    output.write(f"  A Records:\n")
                    for record in a_records:
                        output.write(f"    {record}\n")
                except Exception as e:
                    output.write(f"  A Records: Error - {str(e)}\n")
                
                # Get NS records
                try:
                    ns_records = dns.resolver.resolve(domain, 'NS')
                    output.write(f"  Name Servers:\n")
                    for record in ns_records:
                        output.write(f"    {record}\n")
                except Exception as e:
                    output.write(f"  Name Servers: Error - {str(e)}\n")
                
                # Get MX records
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    output.write(f"  Mail Servers:\n")
                    for record in mx_records:
                        output.write(f"    {record.preference} {record.exchange}\n")
                except Exception as e:
                    output.write(f"  Mail Servers: Error - {str(e)}\n")
                
            except Exception as e:
                output.write(f"Error retrieving DNS information: {str(e)}\n")
        
        return output.getvalue()
    
    except Exception as e:
        return f"Error running WHOIS lookup: {str(e)}"


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