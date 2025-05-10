#!/usr/bin/env python3
"""
This script resets the passwords for the default users (admin and standard)
to the specified password. Run this script with Flask app context.
"""
import os
import sys
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash

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

def reset_passwords(new_password="probeopS1@"):
    """Reset passwords for the admin and standard users"""
    
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
        
        # Find the users
        admin_user = session.query(User).filter_by(username="admin").first()
        standard_user = session.query(User).filter_by(username="standard").first()
        
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
            session.commit()
            print(f"Successfully updated {users_updated} user passwords to '{new_password}'")
        else:
            print("No users were updated")
        
    except Exception as e:
        print(f"ERROR: Failed to update passwords: {str(e)}")
        session.rollback()
        return False
    finally:
        session.close()
    
    return True

if __name__ == "__main__":
    # Allow custom password as command line argument
    if len(sys.argv) > 1:
        new_password = sys.argv[1]
        reset_passwords(new_password)
    else:
        reset_passwords()