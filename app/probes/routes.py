import subprocess
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import User, ProbeJob, ProbeResult
from app.db.session import get_db
from app.probes.schemas import (
    PingRequest, TracerouteRequest, DnsRequest, WhoisRequest, 
    CurlRequest, PortCheckRequest, ProbeResponse, ProbeJobResponse
)
from app.utils.command import (
    run_ping, run_traceroute, run_dns_lookup, 
    run_whois, run_curl, run_port_check
)
from app.utils.response import format_response

router = APIRouter()

# Helper to save probe results
def save_probe_result(db: Session, user_id: int, probe_type: str, target: str, result: str):
    """Save probe job and result to database"""
    # Create new job
    new_job = ProbeJob(
        user_id=user_id,
        probe_type=probe_type,
        target=target,
        created_at=datetime.utcnow()
    )
    
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    
    # Create result linked to job
    new_result = ProbeResult(
        job_id=new_job.id,
        result=result,
        created_at=datetime.utcnow()
    )
    
    db.add(new_result)
    db.commit()
    
    return new_job, new_result

@router.post("/ping", response_model=ProbeResponse)
async def ping(
    request: PingRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run ping on a target host"""
    try:
        # Execute ping command
        result = run_ping(request.host, request.count)
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="ping", 
            target=request.host,
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="ping",
            target=request.host,
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing ping: {str(e)}"
        )

@router.post("/traceroute", response_model=ProbeResponse)
async def traceroute(
    request: TracerouteRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run traceroute on a target host"""
    try:
        # Execute traceroute command
        result = run_traceroute(request.host, request.max_hops)
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="traceroute", 
            target=request.host,
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="traceroute",
            target=request.host,
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing traceroute: {str(e)}"
        )

@router.post("/dns", response_model=ProbeResponse)
async def dns_lookup(
    request: DnsRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run DNS lookup on a domain"""
    try:
        # Execute DNS lookup command
        result = run_dns_lookup(request.domain, request.record_type)
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="dns", 
            target=f"{request.domain} ({request.record_type})",
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="dns",
            target=f"{request.domain} ({request.record_type})",
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing DNS lookup: {str(e)}"
        )

@router.post("/whois", response_model=ProbeResponse)
async def whois(
    request: WhoisRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run WHOIS lookup on a domain"""
    try:
        # Execute WHOIS lookup command
        result = run_whois(request.domain)
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="whois", 
            target=request.domain,
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="whois",
            target=request.domain,
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing WHOIS lookup: {str(e)}"
        )

@router.post("/curl", response_model=ProbeResponse)
async def curl(
    request: CurlRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run curl on a URL"""
    try:
        # Execute curl command
        result = run_curl(
            request.url, 
            request.method, 
            request.headers, 
            request.data, 
            request.timeout
        )
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="curl", 
            target=request.url,
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="curl",
            target=request.url,
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing curl: {str(e)}"
        )

@router.post("/port", response_model=ProbeResponse)
async def port_check(
    request: PortCheckRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check if a port is open on a host"""
    try:
        # Execute port check
        result = run_port_check(request.host, request.port, request.timeout)
        
        # Save to database
        job, _ = save_probe_result(
            db=db, 
            user_id=current_user.id, 
            probe_type="port", 
            target=f"{request.host}:{request.port}",
            result=result
        )
        
        return format_response(
            success=True,
            probe_type="port",
            target=f"{request.host}:{request.port}",
            result=result,
            job_id=job.id
        )
    except subprocess.SubprocessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing port check: {str(e)}"
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
    # Base query for user's probe jobs
    query = db.query(ProbeJob).filter(ProbeJob.user_id == current_user.id)
    
    # Apply probe_type filter if provided
    if probe_type:
        query = query.filter(ProbeJob.probe_type == probe_type)
    
    # Order by creation date (newest first) and apply pagination
    jobs = query.order_by(ProbeJob.created_at.desc()).offset(offset).limit(limit).all()
    
    # Prepare response with job history
    result = []
    for job in jobs:
        # Get the result for this job
        result_record = db.query(ProbeResult).filter(ProbeResult.job_id == job.id).first()
        
        result.append(
            ProbeJobResponse(
                id=job.id,
                probe_type=job.probe_type,
                target=job.target,
                created_at=job.created_at,
                result=result_record.result if result_record else None
            )
        )
    
    return result
