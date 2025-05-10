"""
API key management routes for ProbeOps API
"""
import logging

from flask import Blueprint, request, jsonify, g

# Import directly from flask_server (which is the primary implementation)
from flask_server import db, User, ApiKey, login_required, admin_required, role_required, tier_required

# Helper function to get current user
def get_current_user():
    """Utility to get current user from g"""
    return g.current_user if hasattr(g, 'current_user') else None

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
bp = Blueprint("apikeys", __name__, url_prefix="/apikeys")


@bp.route("/", methods=["GET"])
@login_required
def list_apikeys():
    """List API keys for the current user"""
    current_user = get_current_user()
    
    # Admin can see all keys with user information
    if current_user.is_admin_user() and request.args.get("all") == "true":
        keys = ApiKey.query.all()
        return jsonify({
            "api_keys": [{
                **key.to_dict(),
                "user": {
                    "id": key.user.id,
                    "username": key.user.username,
                    "email": key.user.email
                }
            } for key in keys]
        })
    
    # Regular users can only see their own keys
    keys = ApiKey.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        "api_keys": [key.to_dict() for key in keys]
    })


@bp.route("/", methods=["POST"])
@login_required
def create_apikey():
    """Create a new API key for the current user"""
    current_user = get_current_user()
    data = request.json or {}
    description = data.get("description", "API key")
    
    # Create new API key
    api_key = ApiKey(
        user=current_user,
        key=ApiKey.generate_key(),
        description=description
    )
    
    try:
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            "message": "API key created successfully",
            "api_key": api_key.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating API key: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<int:key_id>", methods=["GET"])
@login_required
def get_apikey(key_id):
    """Get API key by ID"""
    current_user = get_current_user()
    
    # Admin can see any key
    if current_user.is_admin_user():
        key = ApiKey.query.get(key_id)
    else:
        # Regular users can only see their own keys
        key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    
    if not key:
        return jsonify({"error": "API key not found"}), 404
    
    return jsonify({
        "api_key": key.to_dict()
    })


@bp.route("/<int:key_id>", methods=["PUT"])
@login_required
def update_apikey(key_id):
    """Update API key"""
    current_user = get_current_user()
    
    # Admin can update any key
    if current_user.is_admin_user():
        key = ApiKey.query.get(key_id)
    else:
        # Regular users can only update their own keys
        key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    
    if not key:
        return jsonify({"error": "API key not found"}), 404
    
    data = request.json or {}
    
    # Update key fields
    if "description" in data:
        key.description = data["description"]
    if "is_active" in data:
        key.is_active = data["is_active"]
    
    try:
        db.session.commit()
        return jsonify({
            "message": "API key updated successfully",
            "api_key": key.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating API key: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<int:key_id>", methods=["DELETE"])
@login_required
def delete_apikey(key_id):
    """Delete API key"""
    current_user = get_current_user()
    
    # Admin can delete any key
    if current_user.is_admin_user():
        key = ApiKey.query.get(key_id)
    else:
        # Regular users can only delete their own keys
        key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    
    if not key:
        return jsonify({"error": "API key not found"}), 404
    
    try:
        db.session.delete(key)
        db.session.commit()
        return jsonify({
            "message": "API key deleted successfully"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting API key: {str(e)}")
        return jsonify({"error": str(e)}), 500