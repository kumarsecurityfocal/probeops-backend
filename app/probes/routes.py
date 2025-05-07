from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.db.models import User, ProbeJob, ProbeResult
from app.auth.dependencies import get_current_user
from app.probes.schemas import (
    PingRequest, 
    TracerouteRequest, 
    DnsRequest, 
    WhoisRequest, 
    CurlRequest, 
    PortCheckRequest,
    ProbeResponse,
    ProbeJobResponse
)
from app.utils.command import (
    run_ping, 
    run_traceroute, 
    run_dns_lookup, 
    run_whois, 
    run_curl, 
    run_port_check
)
from app.utils.response import format_response

# Create router
router = APIRouter()

def save_probe_result(db: Session, user_id: int, probe_type: str, target: str, result: str):
    """Save probe job and result to database"""
    # Create the probe job
    probe_job = ProbeJob(
        user_id=user_id,
        probe_type=probe_type,
        target=target
    )
    
    # Add the job to the database
    db.add(probe_job)
    db.flush()  # Flush to get the job ID
    
    # Create the probe result
    probe_result = ProbeResult(
        job_id=probe_job.id,
        result=result
    )
    
    # Add the result to the database
    db.add(probe_result)
    db.commit()
    
    return probe_job.id

@router.post("/ping", response_model=ProbeResponse)
async def ping(
    request: PingRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run ping on a target host"""
    result = run_ping(request.host, request.count)
    success = not result.startswith("ERROR")
    
    # Save to database
    job_id = save_probe_result(db, current_user.id, "ping", request.host, result)
    
    # Return response
    return format_response(success, "ping", request.host, result, job_id)

@router.post("/traceroute", response_model=ProbeResponse)
async def traceroute(
    request: TracerouteRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run traceroute on a target host"""
    result = run_traceroute(request.host, request.max_hops)
    success = not result.startswith("ERROR")
    
    # Save to database
    job_id = save_probe_result(db, current_user.id, "traceroute", request.host, result)
    
    # Return response
    return format_response(success, "traceroute", request.host, result, job_id)

@router.post("/dns", response_model=ProbeResponse)
async def dns_lookup(
    request: DnsRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run DNS lookup on a domain"""
    result = run_dns_lookup(request.domain, request.record_type)
    success = not result.startswith("ERROR")
    
    # Save to database
    job_id = save_probe_result(
        db, 
        current_user.id, 
        f"dns-{request.record_type}", 
        request.domain, 
        result
    )
    
    # Return response
    return format_response(
        success, 
        f"dns-{request.record_type}", 
        request.domain, 
        result, 
        job_id
    )

@router.post("/whois", response_model=ProbeResponse)
async def whois(
    request: WhoisRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run WHOIS lookup on a domain"""
    result = run_whois(request.domain)
    success = not result.startswith("ERROR")
    
    # Save to database
    job_id = save_probe_result(db, current_user.id, "whois", request.domain, result)
    
    # Return response
    return format_response(success, "whois", request.domain, result, job_id)

@router.post("/curl", response_model=ProbeResponse)
async def curl(
    request: CurlRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run curl on a URL"""
    result = run_curl(
        request.url, 
        request.method, 
        request.headers, 
        request.data, 
        request.timeout
    )
    success = not result.startswith("ERROR")
    
    # Save to database
    job_id = save_probe_result(
        db, 
        current_user.id, 
        f"curl-{request.method}", 
        request.url, 
        result
    )
    
    # Return response
    return format_response(
        success, 
        f"curl-{request.method}", 
        request.url, 
        result, 
        job_id
    )

@router.post("/port", response_model=ProbeResponse)
async def port_check(
    request: PortCheckRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check if a port is open on a host"""
    result = run_port_check(request.host, request.port, request.timeout)
    success = not result.startswith("Error")
    
    # Save to database
    job_id = save_probe_result(
        db, 
        current_user.id, 
        "port", 
        f"{request.host}:{request.port}", 
        result
    )
    
    # Return response
    return format_response(
        success, 
        "port", 
        f"{request.host}:{request.port}", 
        result, 
        job_id
    )

@router.get("/history", response_model=List[ProbeJobResponse])
async def get_probe_history(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    probe_type: str = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get probe job history for the current user"""
    # Build the query
    query = db.query(ProbeJob).filter(ProbeJob.user_id == current_user.id)
    
    # Filter by probe type if provided
    if probe_type:
        query = query.filter(ProbeJob.probe_type.ilike(f"%{probe_type}%"))
    
    # Order by creation date descending
    query = query.order_by(desc(ProbeJob.created_at))
    
    # Apply pagination
    jobs = query.offset(offset).limit(limit).all()
    
    # Get the latest result for each job
    job_responses = []
    for job in jobs:
        latest_result = db.query(ProbeResult)\
            .filter(ProbeResult.job_id == job.id)\
            .order_by(desc(ProbeResult.created_at))\
            .first()
        
        job_dict = {
            "id": job.id,
            "probe_type": job.probe_type,
            "target": job.target,
            "created_at": job.created_at,
            "result": latest_result.result if latest_result else None
        }
        
        job_responses.append(job_dict)
    
    return job_responses