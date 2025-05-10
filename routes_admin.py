"""
Admin management routes for ProbeOps API
"""
import logging
from datetime import datetime, timedelta

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
    if user.id == current_user.id:
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
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    
    # Build query with optional filters
    query = User.query
    
    if role:
        if role not in User.VALID_ROLES:
            return jsonify({"error": f"Invalid role filter. Must be one of: {', '.join(User.VALID_ROLES)}"}), 400
        query = query.filter_by(role=role)
    
    if tier:
        if tier not in User.VALID_TIERS:
            return jsonify({"error": f"Invalid tier filter. Must be one of: {', '.join(User.VALID_TIERS)}"}), 400
        query = query.filter_by(subscription_tier=tier)
    
    # Get total count for pagination
    total = query.count()
    
    # Apply pagination and get users
    users = query.order_by(User.id).limit(limit).offset(offset).all()
    
    # Return with pagination metadata
    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
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
    
    return jsonify({
        "user": user.to_dict(),
        "api_keys": [key.to_dict() for key in api_keys],
        "stats": {
            "total_api_keys": len(api_keys),
            "total_probes": total_probes,
            "probe_counts": probe_counts,
            "latest_activity": latest_activity
        }
    })


@bp.route("/status", methods=["GET"])
@admin_required
def admin_status():
    """Admin status endpoint"""
    user_count = User.query.count()
    admin_count = User.query.filter_by(role=User.ROLE_ADMIN).count()
    active_count = User.query.filter_by(is_active=True).count()
    inactive_count = user_count - active_count
    
    # Get active users in the last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = db.session.query(
        db.func.count(db.distinct(ProbeJob.user_id))
    ).filter(ProbeJob.created_at >= thirty_days_ago).scalar() or 0
    
    # Count users by subscription tier
    tier_counts = {}
    for tier in User.VALID_TIERS:
        tier_counts[tier] = User.query.filter_by(subscription_tier=tier).count()
    
    # Count users by role
    role_counts = {}
    for role in User.VALID_ROLES:
        role_counts[role] = User.query.filter_by(role=role).count()
    
    # Count probe jobs by type
    probe_stats = db.session.query(
        ProbeJob.probe_type, 
        db.func.count(ProbeJob.id).label('count')
    ).group_by(ProbeJob.probe_type).all()
    
    probe_counts = {probe_type: count for probe_type, count in probe_stats}
    total_probes = sum(probe_counts.values())
    
    return jsonify({
        "status": "ok",
        "users": {
            "total": user_count,
            "active": active_count,
            "inactive": inactive_count,
            "admin_count": admin_count,
            "active_last_30_days": recent_users,
            "by_tier": tier_counts,
            "by_role": role_counts
        },
        "probes": {
            "total": total_probes,
            "by_type": probe_counts
        }
    })