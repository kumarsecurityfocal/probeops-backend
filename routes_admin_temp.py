"""
Admin management routes for ProbeOps API
"""
import logging
from datetime import datetime, timedelta, time

from flask import Blueprint, request, jsonify, current_app, g
from sqlalchemy.exc import IntegrityError

# Import directly from flask_server (which is the primary implementation)
from flask_server import db, User, ApiKey, ProbeJob, login_required, admin_required, role_required, tier_required, create_jwt_token

# Helper function to get current user
def get_current_user():
    """Utility to get current user from g"""
    return g.current_user if hasattr(g, 'current_user') else None

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/login", methods=["POST"])
def admin_login():
    """Admin login endpoint"""
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check required fields
    if "username" not in data or "password" not in data:
        return jsonify({"error": "Missing username or password"}), 400
    
    # Find user by username
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not user.verify_password(data["password"]):
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Check if user is active
    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403
    
    # Check if user has admin role
    if user.role != User.ROLE_ADMIN:
        return jsonify({"error": "Admin privileges required"}), 403
    
    # Generate JWT token
    token = create_jwt_token(user)
    
    return jsonify({
        "message": "Admin login successful",
        "token": token,
        "user": user.to_dict()
    })


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):
    """Update user role (promote to admin or demote to regular user)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get current admin user
    current_user = get_current_user()
    
    # Prevent users from changing their own role (security measure)
    if current_user and user.id == current_user.id:
        return jsonify({"error": "You cannot change your own role"}), 403
    
    data = request.json
    if not data or "role" not in data:
        return jsonify({"error": "No role provided"}), 400
    
    role = data["role"]
    if role not in User.VALID_ROLES:
        return jsonify({
            "error": f"Invalid role. Must be one of: {', '.join(User.VALID_ROLES)}"
        }), 400
    
    # Update user role
    user.role = role
    user.is_admin = (role == User.ROLE_ADMIN)  # Update legacy field for backward compatibility
    
    try:
        db.session.commit()
        return jsonify({
            "message": f"User role updated to {role} successfully",
            "user": user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user role: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/users/<int:user_id>/promote", methods=["POST"])
@admin_required
def promote_user(user_id):
    """Promote user to admin role (legacy endpoint)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get current admin user
    current_user = get_current_user()
    
    # Prevent users from changing their own role (security measure)
    if current_user and user.id == current_user.id:
        return jsonify({"error": "You cannot change your own role"}), 403
    
    # Update user role to admin
    user.role = User.ROLE_ADMIN
    user.is_admin = True  # Update legacy field for backward compatibility
    
    try:
        db.session.commit()
        return jsonify({
            "message": "User promoted to admin successfully",
            "user": user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error promoting user: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/users/<int:user_id>/tier", methods=["POST"])
@admin_required
def update_subscription_tier(user_id):
    """Update user subscription tier"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    data = request.json
    if not data or "tier" not in data:
        return jsonify({"error": "No tier provided"}), 400
    
    tier = data["tier"]
    if tier not in User.VALID_TIERS:
        return jsonify({
            "error": f"Invalid tier. Must be one of: {', '.join(User.VALID_TIERS)}"
        }), 400
    
    # Update user subscription tier
    user.subscription_tier = tier
    
    try:
        db.session.commit()
        return jsonify({
            "message": f"User subscription tier updated to {tier} successfully",
            "user": user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating subscription tier: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/users/<int:user_id>/status", methods=["POST"])
@admin_required
def toggle_user_active_status(user_id):
    """Activate or deactivate a user account"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get current admin user
    current_user = get_current_user()
    
    # Prevent users from deactivating themselves (security measure)
    if current_user and user.id == current_user.id:
        return jsonify({"error": "You cannot change your own active status"}), 403
    
    data = request.json
    if not data or "is_active" not in data:
        return jsonify({"error": "Missing is_active parameter"}), 400
    
    # Get the desired active status (true or false)
    is_active = bool(data["is_active"])
    
    # Update user's active status
    user.is_active = is_active
    
    try:
        db.session.commit()
        status_text = "activated" if is_active else "deactivated"
        return jsonify({
            "message": f"User {status_text} successfully",
            "user": user.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user status: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/users", methods=["GET"])
@admin_required
def list_all_users():
    """List all users with filtering and pagination"""
    # Get filter parameters
    role = request.args.get("role")
    tier = request.args.get("tier")
    active_status = request.args.get("active")
    search_query = request.args.get("q")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    sort_by = request.args.get("sort", "id")
    sort_order = request.args.get("order", "asc")
    
    # Build query with optional filters
    query = User.query
    
    # Apply role filter
    if role:
        if role not in User.VALID_ROLES:
            return jsonify({"error": f"Invalid role filter. Must be one of: {', '.join(User.VALID_ROLES)}"}), 400
        query = query.filter_by(role=role)
    
    # Apply tier filter
    if tier:
        if tier not in User.VALID_TIERS:
            return jsonify({"error": f"Invalid tier filter. Must be one of: {', '.join(User.VALID_TIERS)}"}), 400
        query = query.filter_by(subscription_tier=tier)
    
    # Apply active status filter
    if active_status is not None:
        is_active = active_status.lower() in ['true', '1', 'yes']
        query = query.filter_by(is_active=is_active)
    
    # Apply search query if provided
    if search_query:
        search_term = f"%{search_query}%"
        # Search by username or email
        query = query.filter(db.or_(
            User.username.ilike(search_term),
            User.email.ilike(search_term)
        ))
    
    # Apply sorting
    if sort_by == "username":
        if sort_order.lower() == "desc":
            query = query.order_by(User.username.desc())
        else:
            query = query.order_by(User.username.asc())
    elif sort_by == "email":
        if sort_order.lower() == "desc":
            query = query.order_by(User.email.desc())
        else:
            query = query.order_by(User.email.asc())
    elif sort_by == "created_at":
        if sort_order.lower() == "desc":
            query = query.order_by(User.created_at.desc())
        else:
            query = query.order_by(User.created_at.asc())
    else:  # Default: sort by ID
        if sort_order.lower() == "desc":
            query = query.order_by(User.id.desc())
        else:
            query = query.order_by(User.id.asc())
    
    # Get total count for pagination
    total = query.count()
    
    # Apply pagination and get users
    users = query.limit(limit).offset(offset).all()
    
    # Return with pagination metadata and filter information
    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
        "filters": {
            "role": role,
            "tier": tier,
            "active": active_status,
            "search": search_query
        },
        "sort": {
            "field": sort_by,
            "order": sort_order
        },
        "users": [user.to_dict() for user in users]
    })


@bp.route("/users/<int:user_id>", methods=["GET"])
@admin_required
def get_user_details(user_id):
    """Get detailed user information"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get user's API keys and probe job counts
    api_keys = ApiKey.query.filter_by(user_id=user.id).all()
    
    # Count probe jobs by type
    probe_stats = db.session.query(
        ProbeJob.probe_type, 
        db.func.count(ProbeJob.id).label('count')
    ).filter_by(user_id=user.id).group_by(ProbeJob.probe_type).all()
    
    probe_counts = {probe_type: count for probe_type, count in probe_stats}
    total_probes = sum(probe_counts.values())
    
    # Get latest activity timestamp
    latest_probe = db.session.query(db.func.max(ProbeJob.created_at)).filter_by(user_id=user.id).scalar()
    latest_activity = latest_probe.isoformat() if latest_probe else None
    
    # Get recent probe history (last 10 probes)
    recent_probes = ProbeJob.query.filter_by(user_id=user.id).order_by(ProbeJob.created_at.desc()).limit(10).all()
    
    # Get API key usage metrics
    api_key_usage = []
    for key in api_keys:
        # Count probes per API key (requires filtering by API key in the actual application logs)
        # Here we're using a simplified approach
        usage = {
            "key_id": key.id,
            "key_description": key.description or "No description",
            "last_used": key.last_used_at.isoformat() if key.last_used_at else None,
            "is_active": key.is_active
        }
        api_key_usage.append(usage)
    
    # Calculate activity metrics
    today = datetime.utcnow().date()
    one_day_ago = today - timedelta(days=1)
    one_week_ago = today - timedelta(days=7)
    one_month_ago = today - timedelta(days=30)
    
    # Count probes in different time periods
    probes_today = ProbeJob.query.filter(
        ProbeJob.user_id == user.id,
        ProbeJob.created_at >= datetime.combine(today, datetime.min.time())
    ).count()
    
    probes_last_day = ProbeJob.query.filter(
        ProbeJob.user_id == user.id,
        ProbeJob.created_at >= datetime.combine(one_day_ago, datetime.min.time())
    ).count()
    
    probes_last_week = ProbeJob.query.filter(
        ProbeJob.user_id == user.id,
        ProbeJob.created_at >= datetime.combine(one_week_ago, datetime.min.time())
    ).count()
    
    probes_last_month = ProbeJob.query.filter(
        ProbeJob.user_id == user.id,
        ProbeJob.created_at >= datetime.combine(one_month_ago, datetime.min.time())
    ).count()
    
    # Calculate success rate
    successful_probes = ProbeJob.query.filter_by(user_id=user.id, success=True).count()
    success_rate = (successful_probes / total_probes * 100) if total_probes > 0 else 0
    
    return jsonify({
        "user": user.to_dict(),
        "api_keys": [key.to_dict() for key in api_keys],
        "api_key_usage": api_key_usage,
        "stats": {
            "total_api_keys": len(api_keys),
            "total_probes": total_probes,
            "probe_counts": probe_counts,
            "latest_activity": latest_activity,
            "activity_metrics": {
                "probes_today": probes_today,
                "probes_last_day": probes_last_day,
                "probes_last_week": probes_last_week,
                "probes_last_month": probes_last_month
            },
            "success_rate": round(success_rate, 2)
        },
        "recent_probes": [probe.to_dict() for probe in recent_probes]
    })


@bp.route("/rate-limits", methods=["GET"])
@admin_required
def list_rate_limits():
    """List all rate limit configurations"""
    # Import RateLimitConfig from models to avoid circular import
    from models import RateLimitConfig
    
    configs = RateLimitConfig.query.all()
    
    # Get default configurations for reference
    default_configs = {cfg['tier']: cfg for cfg in RateLimitConfig.get_default_configs()}
    
    # Build response with current configs and default values
    response = []
    for tier in User.VALID_TIERS:
        # Find existing config for this tier
        config = next((cfg for cfg in configs if cfg.tier == tier), None)
        
        # If no config exists, use default values
        if not config:
            default = default_configs.get(tier, {})
            item = {
                "tier": tier,
                "daily_limit": default.get('daily_limit', 0),
                "monthly_limit": default.get('monthly_limit', 0),
                "min_interval_minutes": default.get('min_interval_minutes', 0),
                "is_custom": False,
                "updated_at": None,
                "updated_by_user_id": None
            }
        else:
            item = config.to_dict()
            item["is_custom"] = True
        
        response.append(item)
    
    return jsonify({
        "rate_limits": response
    })


@bp.route("/rate-limits/<tier>", methods=["GET"])
@admin_required
def get_rate_limit(tier):
    """Get rate limit configuration for a specific tier"""
    # Import RateLimitConfig from models to avoid circular import
    from models import RateLimitConfig
    
    if tier not in User.VALID_TIERS:
        return jsonify({
            "error": f"Invalid tier. Must be one of: {', '.join(User.VALID_TIERS)}"
        }), 400
    
    # Try to find existing config
    config = RateLimitConfig.query.filter_by(tier=tier).first()
    
    # If no config exists, use default values
    if not config:
        default_configs = {cfg['tier']: cfg for cfg in RateLimitConfig.get_default_configs()}
        default = default_configs.get(tier, {})
        return jsonify({
            "tier": tier,
            "daily_limit": default.get('daily_limit', 0),
            "monthly_limit": default.get('monthly_limit', 0),
            "min_interval_minutes": default.get('min_interval_minutes', 0),
            "is_custom": False,
            "updated_at": None,
            "updated_by_user_id": None
        })
    
    # Return existing config
    response = config.to_dict()
    response["is_custom"] = True
    return jsonify(response)


@bp.route("/rate-limits/<tier>", methods=["POST"])
@admin_required
def update_rate_limit(tier):
    """Update rate limit configuration for a specific tier"""
    # Import RateLimitConfig from models to avoid circular import
    from models import RateLimitConfig
    
    if tier not in User.VALID_TIERS:
        return jsonify({
            "error": f"Invalid tier. Must be one of: {', '.join(User.VALID_TIERS)}"
        }), 400
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Validate required fields
    required_fields = ["daily_limit", "monthly_limit", "min_interval_minutes"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate numeric values
    for field in required_fields:
        if not isinstance(data[field], (int, float)) or data[field] < 0:
            return jsonify({"error": f"{field} must be a positive number"}), 400
    
    # Get current user
    current_user = get_current_user()
    
    # Try to find existing config
    config = RateLimitConfig.query.filter_by(tier=tier).first()
    
    # If no config exists, create a new one
    if not config:
        config = RateLimitConfig()
        config.tier = tier
        config.daily_limit = data["daily_limit"]
        config.monthly_limit = data["monthly_limit"]
        config.min_interval_minutes = data["min_interval_minutes"]
        config.updated_by_user_id = current_user.id if current_user else None
        db.session.add(config)
    else:
        # Update existing config
        config.daily_limit = data["daily_limit"]
        config.monthly_limit = data["monthly_limit"]
        config.min_interval_minutes = data["min_interval_minutes"]
        config.updated_by_user_id = current_user.id if current_user else None
    
    try:
        db.session.commit()
        response = config.to_dict()
        response["is_custom"] = True
        return jsonify({
            "message": f"Rate limit configuration for {tier} tier updated successfully",
            "rate_limit": response
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating rate limit config: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/rate-limits/<tier>/reset", methods=["POST"])
@admin_required
def reset_rate_limit(tier):
    """Reset rate limit configuration for a specific tier to default values"""
    # Import RateLimitConfig from models to avoid circular import
    from models import RateLimitConfig
    
    if tier not in User.VALID_TIERS:
        return jsonify({
            "error": f"Invalid tier. Must be one of: {', '.join(User.VALID_TIERS)}"
        }), 400
    
    # Find existing config
    config = RateLimitConfig.query.filter_by(tier=tier).first()
    if not config:
        return jsonify({
            "message": f"No custom configuration exists for {tier} tier",
            "tier": tier,
            "is_default": True
        })
    
    # Delete custom config to restore defaults
    try:
        db.session.delete(config)
        db.session.commit()
        
        # Get default values
        default_configs = {cfg['tier']: cfg for cfg in RateLimitConfig.get_default_configs()}
        default = default_configs.get(tier, {})
        
        return jsonify({
            "message": f"Rate limit configuration for {tier} tier reset to default values",
            "tier": tier,
            "daily_limit": default.get('daily_limit', 0),
            "monthly_limit": default.get('monthly_limit', 0),
            "min_interval_minutes": default.get('min_interval_minutes', 0),
            "is_default": True
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error resetting rate limit config: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/status", methods=["GET"])
@admin_required
def admin_status():
    """Admin status endpoint"""
    # Import server_status directly from flask_server to avoid SQLAlchemy context issues
    from flask_server import server_status

    # Just proxy to the original server_status function
    return server_status()
