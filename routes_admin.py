"""
Admin management routes for ProbeOps API
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, current_app, g
from sqlalchemy.exc import IntegrityError

# Import directly from flask_server (which is the primary implementation)
from flask_server import db, User, ApiKey, login_required, admin_required, role_required, tier_required, create_jwt_token

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


@bp.route("/users/<int:user_id>/promote", methods=["POST"])
@admin_required
def promote_user(user_id):
    """Promote user to admin role"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
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


@bp.route("/status", methods=["GET"])
@admin_required
def admin_status():
    """Admin status endpoint"""
    user_count = User.query.count()
    admin_count = User.query.filter_by(role=User.ROLE_ADMIN).count()
    
    # Count users by subscription tier
    tier_counts = {}
    for tier in User.VALID_TIERS:
        tier_counts[tier] = User.query.filter_by(subscription_tier=tier).count()
    
    return jsonify({
        "status": "ok",
        "user_count": user_count,
        "admin_count": admin_count,
        "subscription_tiers": tier_counts
    })