from datetime import datetime
from typing import Any, Dict

def format_response(
    success: bool, 
    probe_type: str, 
    target: str, 
    result: str,
    job_id: int
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
        "timestamp": datetime.utcnow()
    }
