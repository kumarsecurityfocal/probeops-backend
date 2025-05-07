"""
User management routes for ProbeOps API
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify
from sqlalchemy.exc import IntegrityError

from models import db, User, ApiKey
from auth import login_required, admin_required, current_user, create_jwt_token

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
bp = Blueprint("users", __name__, url_prefix="/users")


@bp.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check required fields
    required_fields = ["username", "email", "password"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate data
    if len(data["username"]) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(data["password"]) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Create new user
    try:
        user = User(
            username=data["username"],
            email=data["email"],
            is_active=True,
            is_admin=False
        )
        user.password = data["password"]  # This will be hashed
        
        db.session.add(user)
        db.session.commit()
        
        # Create API key for the user
        api_key = ApiKey(
            user=user,
            key=ApiKey.generate_key(),
            description="Default API key"
        )
        db.session.add(api_key)
        db.session.commit()
        
        return jsonify({
            "message": "User registered successfully",
            "user": user.to_dict(),
            "api_key": api_key.key
        }), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/login", methods=["POST"])
def login():
    """Login and get JWT token"""
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
    
    # Generate JWT token
    token = create_jwt_token(user)
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": user.to_dict()
    })


@bp.route("/me", methods=["GET"])
@login_required
def get_current_user_info():
    """Get current user information"""
    return jsonify({
        "user": current_user.to_dict()
    })


@bp.route("/", methods=["GET"])
@admin_required
def list_users():
    """List all users (admin only)"""
    users = User.query.all()
    return jsonify({
        "users": [user.to_dict() for user in users]
    })


@bp.route("/<int:user_id>", methods=["GET"])
@admin_required
def get_user(user_id):
    """Get user by ID (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "user": user.to_dict()
    })


@bp.route("/<int:user_id>", methods=["PUT"])
@admin_required
def update_user(user_id):
    """Update user (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Update user fields
    if "username" in data:
        user.username = data["username"]
    if "email" in data:
        user.email = data["email"]
    if "password" in data:
        user.password = data["password"]
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "is_admin" in data:
        user.is_admin = data["is_admin"]
    
    try:
        db.session.commit()
        return jsonify({
            "message": "User updated successfully",
            "user": user.to_dict()
        })
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user: {str(e)}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    """Delete user (admin only)"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({
            "message": "User deleted successfully"
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        return jsonify({"error": str(e)}), 500