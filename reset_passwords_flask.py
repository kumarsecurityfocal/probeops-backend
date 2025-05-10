"""
Reset passwords for the ProbeOps API default users.
"""
from flask import Flask, current_app
from werkzeug.security import generate_password_hash
import os
import sys

# Import Flask app from main.py or create a new one
try:
    from main import app
except ImportError:
    app = Flask(__name__)
    # Configure app
    app.config.update(
        SECRET_KEY=os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    # Import your models
    try:
        from probeops.models import db, User
    except ImportError:
        from models import db, User
    
    # Initialize extensions
    db.init_app(app)

@app.cli.command("reset-default-passwords")
def reset_default_passwords():
    """Reset passwords for the admin and standard users to probeopS1@"""
    with app.app_context():
        try:
            # Import models within app context
            try:
                from probeops.models import User, db
            except ImportError:
                from models import User, db
            
            # Set the new password
            new_password = "probeopS1@"
            
            # Find users
            admin_user = User.query.filter_by(username="admin").first()
            standard_user = User.query.filter_by(username="standard").first()
            
            users_updated = 0
            
            # Update admin password if user exists
            if admin_user:
                # Update password hash field
                if hasattr(admin_user, 'hashed_password'):
                    admin_user.hashed_password = generate_password_hash(new_password)
                # Use password setter if available
                try:
                    admin_user.password = new_password
                except Exception:
                    pass  # If no setter is defined, we already set the hash directly
                    
                users_updated += 1
                print(f"Updated password for admin user ({admin_user.username})")
            else:
                print("WARNING: Admin user not found")
            
            # Update standard user password if user exists
            if standard_user:
                # Update password hash field
                if hasattr(standard_user, 'hashed_password'):
                    standard_user.hashed_password = generate_password_hash(new_password)
                # Use password setter if available
                try:
                    standard_user.password = new_password
                except Exception:
                    pass  # If no setter is defined, we already set the hash directly
                    
                users_updated += 1
                print(f"Updated password for standard user ({standard_user.username})")
            else:
                print("WARNING: Standard user not found")
            
            # Commit changes
            if users_updated > 0:
                db.session.commit()
                print(f"Successfully updated {users_updated} user passwords to '{new_password}'")
            else:
                print("No users were updated")
                
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to update passwords: {str(e)}")


if __name__ == "__main__":
    # Run directly for testing
    with app.app_context():
        reset_default_passwords()