#!/usr/bin/env python3
"""
This script updates the missing email fields for admin and standard users.
"""
import os
import sys
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add the current directory to the path to find the app
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import User model - adjust import path as needed
try:
    from probeops.models import User
    print("Successfully imported User model from probeops.models")
except ImportError:
    try:
        from models import User
        print("Successfully imported User model from models")
    except ImportError:
        print("ERROR: Could not import User model. Make sure you're running this from the correct directory.")
        sys.exit(1)

def fix_user_emails():
    """Update email fields for admin and standard users"""
    
    # Get database URL from environment or use default
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    try:
        # Connect to the database
        engine = create_engine(database_url)
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Find the users by username
        admin_user = session.query(User).filter_by(username="admin").first()
        standard_user = session.query(User).filter_by(username="standard").first()
        
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
            session.commit()
            print(f"Successfully updated {users_updated} user email addresses")
        else:
            print("No users were updated")
        
    except Exception as e:
        print(f"ERROR: Failed to update user emails: {str(e)}")
        session.rollback()
        return False
    finally:
        session.close()
    
    return True

if __name__ == "__main__":
    fix_user_emails()