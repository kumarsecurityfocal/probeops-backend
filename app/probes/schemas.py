from typing import Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator
import re
import ipaddress

class PingRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    count: int = Field(4, ge=1, le=20, description="Number of packets to send")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]{1,253}[a-zA-Z0-9]$', v):
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("Invalid hostname or IP address")
        return v

class TracerouteRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    max_hops: int = Field(30, ge=1, le=64, description="Maximum number of hops")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]{1,253}[a-zA-Z0-9]$', v):
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("Invalid hostname or IP address")
        return v

class DnsRequest(BaseModel):
    domain: str = Field(..., description="Domain name to look up")
    record_type: str = Field("A", description="DNS record type (A, AAAA, MX, TXT, etc.)")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain name"""
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]{1,253}[a-zA-Z0-9]$', v):
            raise ValueError("Invalid domain name")
        return v
    
    @validator('record_type')
    def validate_record_type(cls, v):
        """Validate DNS record type"""
        valid_types = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]
        if v.upper() not in valid_types:
            raise ValueError(f"Invalid DNS record type. Must be one of: {', '.join(valid_types)}")
        return v.upper()

class WhoisRequest(BaseModel):
    domain: str = Field(..., description="Domain name for WHOIS lookup")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain name"""
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]{1,253}[a-zA-Z0-9]$', v):
            raise ValueError("Invalid domain name")
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
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        if v.upper() not in valid_methods:
            raise ValueError(f"Invalid HTTP method. Must be one of: {', '.join(valid_methods)}")
        return v.upper()
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL"""
        if not re.match(r'^https?://[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$', v):
            raise ValueError("Invalid URL format")
        return v

class PortCheckRequest(BaseModel):
    host: str = Field(..., description="Target hostname or IP address")
    port: int = Field(..., ge=1, le=65535, description="Port number to check")
    timeout: int = Field(5, ge=1, le=30, description="Connection timeout in seconds")
    
    @validator('host')
    def validate_hostname(cls, v):
        """Validate hostname or IP address"""
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]{1,253}[a-zA-Z0-9]$', v):
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("Invalid hostname or IP address")
        return v

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
        from_attributes = True  # This replaces orm_mode=True in Pydantic v2