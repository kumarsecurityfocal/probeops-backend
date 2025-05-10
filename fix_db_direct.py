#!/usr/bin/env python3
"""
Direct database script to fix user accounts in ProbeOps API
This connects directly to the PostgreSQL database, bypassing the Flask/SQLAlchemy layer.
"""
import os
import sys
import psycopg2
from werkzeug.security import generate_password_hash

# Configuration
DB_URL = os.environ.get('DATABASE_URL')
NEW_PASSWORD = "probeopS1@"  # Default password
ADMIN_EMAIL = "admin@probeops.com"
STANDARD_EMAIL = "standard@probeops.com"

def fix_user_account():
    """Fix user accounts directly in the database"""
    if not DB_URL:
        print("ERROR: DATABASE_URL environment variable is not set.")
        print("Please set it to your PostgreSQL connection string.")
        return False
    
    print(f"Connecting to database using URL: {DB_URL[:10]}...")
    
    try:
        # Connect to database
        conn = psycopg2.connect(DB_URL)
        cursor = conn.cursor()
        
        # Step 1: Find existing users
        cursor.execute("SELECT id, username, email, hashed_password, password_hash FROM users WHERE username IN ('admin', 'standard')")
        users = cursor.fetchall()
        
        if not users:
            print("WARNING: No users found with usernames 'admin' or 'standard'")
            return False
        
        print(f"Found {len(users)} user(s) to update")
        
        # Generate password hash
        password_hash = generate_password_hash(NEW_PASSWORD)
        
        # Step 2: Update each user
        for user in users:
            user_id, username, email, hashed_password, password_hash_field = user
            
            print(f"User ID: {user_id}, Username: {username}")
            print(f"  Current email: {email or 'None'}")
            
            # Fix email field
            new_email = ADMIN_EMAIL if username == 'admin' else STANDARD_EMAIL
            
            # Fix password fields - update both for compatibility
            updates = []
            params = []
            
            if not email or email != new_email:
                updates.append("email = %s")
                params.append(new_email)
            
            updates.append("hashed_password = %s")
            params.append(password_hash)
            
            updates.append("password_hash = %s")
            params.append(password_hash)
            
            # Add user_id as the last parameter
            params.append(user_id)
            
            # Build and execute update query
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
            cursor.execute(query, params)
            
            # Report changes
            print(f"  Updated email to: {new_email}")
            print(f"  Reset password to: {NEW_PASSWORD}")
        
        # Commit the transaction
        conn.commit()
        print(f"Successfully updated {len(users)} user(s)")
        
        # Close cursor and connection
        cursor.close()
        conn.close()
        
        return True
    
    except Exception as e:
        print(f"ERROR: {str(e)}")
        try:
            conn.rollback()
            conn.close()
        except:
            pass
        return False

if __name__ == "__main__":
    # Allow custom password as command line argument
    if len(sys.argv) > 1:
        NEW_PASSWORD = sys.argv[1]
    
    print(f"Starting user account fix with password: {NEW_PASSWORD}")
    
    if fix_user_account():
        print("\nUser fix complete!")
        print("Try logging in with:")
        print(f"- Email: {ADMIN_EMAIL}, Password: {NEW_PASSWORD}")
        print(f"- Email: {STANDARD_EMAIL}, Password: {NEW_PASSWORD}")
    else:
        print("\nFailed to fix user accounts. See error messages above.")
        sys.exit(1)