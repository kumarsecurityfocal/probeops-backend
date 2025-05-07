from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl, validator
import re

# Input schemas
class PingRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    count: int = Field(4, ge=1, le=20, description="Number of packets to send")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        # Simple validation to prevent command injection
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', v):
            raise ValueError('Invalid hostname or IP address format')
        return v

class TracerouteRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    max_hops: int = Field(30, ge=1, le=64, description="Maximum number of hops")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', v):
            raise ValueError('Invalid hostname or IP address format')
        return v

class DnsRequest(BaseModel):
    domain: str = Field(..., description="Domain name to look up")
    record_type: str = Field("A", description="DNS record type (A, AAAA, MX, TXT, etc.)")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain name"""
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', v):
            raise ValueError('Invalid domain name format')
        return v
    
    @validator('record_type')
    def validate_record_type(cls, v):
        """Validate DNS record type"""
        valid_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV', 'PTR']
        if v.upper() not in valid_types:
            raise ValueError(f'Invalid record type. Must be one of {", ".join(valid_types)}')
        return v.upper()

class WhoisRequest(BaseModel):
    domain: str = Field(..., description="Domain name for WHOIS lookup")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain name"""
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', v):
            raise ValueError('Invalid domain name format')
        return v

class CurlRequest(BaseModel):
    url: str = Field(..., description="URL to request")
    method: str = Field("GET", description="HTTP method to use")
    headers: Optional[Dict[str, str]] = Field(None, description="HTTP headers")
    data: Optional[str] = Field(None, description="Request body data")
    timeout: int = Field(30, ge=1, le=120, description="Request timeout in seconds")
    
    @validator('method')
    def validate_method(cls, v):
        """Validate HTTP method"""
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        if v.upper() not in valid_methods:
            raise ValueError(f'Invalid HTTP method. Must be one of {", ".join(valid_methods)}')
        return v.upper()
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL"""
        # Basic URL validation to prevent command injection
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class PortCheckRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    port: int = Field(..., ge=1, le=65535, description="Port number to check")
    timeout: int = Field(5, ge=1, le=30, description="Connection timeout in seconds")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        if not re.match(r'^[a-zA-Z0-9.\-_]+$', v):
            raise ValueError('Invalid hostname or IP address format')
        return v

# Output schemas
class ProbeResponse(BaseModel):
    success: bool
    probe_type: str
    target: str
    result: str
    job_id: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ProbeJobResponse(BaseModel):
    id: int
    probe_type: str
    target: str
    created_at: datetime
    result: Optional[str]
    
    class Config:
        orm_mode = True
