"""
Fix missing email fields for the ProbeOps API default users.
"""
from flask import Flask, current_app
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

@app.cli.command("fix-user-emails")
def fix_user_emails():
    """Fix missing email addresses for the admin and standard users"""
    with app.app_context():
        try:
            # Import models within app context
            try:
                from probeops.models import User, db
            except ImportError:
                from models import User, db
            
            # Find users by username
            admin_user = User.query.filter_by(username="admin").first()
            standard_user = User.query.filter_by(username="standard").first()
            
            users_updated = 0
            
            # Update admin email if user exists
            if admin_user:
                print(f"Found admin user (ID: {admin_user.id})")
                print(f"  Current email: {admin_user.email}")
                admin_user.email = "admin@probeops.com"
                users_updated += 1
                print(f"  Updated email to: {admin_user.email}")
            else:
                print("WARNING: Admin user not found")
            
            # Update standard user email if user exists
            if standard_user:
                print(f"Found standard user (ID: {standard_user.id})")
                print(f"  Current email: {standard_user.email}")
                standard_user.email = "standard@probeops.com"
                users_updated += 1
                print(f"  Updated email to: {standard_user.email}")
            else:
                print("WARNING: Standard user not found")
            
            # Commit changes
            if users_updated > 0:
                db.session.commit()
                print(f"Successfully updated {users_updated} user email addresses")
            else:
                print("No users were updated")
                
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to update user emails: {str(e)}")

if __name__ == "__main__":
    # Run directly for testing
    with app.app_context():
        fix_user_emails()