#!/usr/bin/env python3
"""
Ultra simple script to fix user accounts in ProbeOps API
This uses psycopg2 if available, or direct SQL if not.
"""
import os
import sys
import hashlib
import base64

# Configuration
DB_URL = os.environ.get('DATABASE_URL')
NEW_PASSWORD = "probeopS1@"  # Default password
ADMIN_EMAIL = "admin@probeops.com"
STANDARD_EMAIL = "standard@probeops.com"

def generate_password_hash(password):
    """Generate a password hash similar to werkzeug without dependencies"""
    # Simple implementation of pbkdf2_sha256 hash similar to werkzeug's default
    method = "pbkdf2:sha256:150000"
    salt = base64.b64encode(hashlib.sha256(os.urandom(8)).digest()).decode('utf-8')[:8]
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                  salt.encode('utf-8'), 150000)
    pw_hash_b64 = base64.b64encode(pw_hash).decode('utf-8')
    return f"{method}${salt}${pw_hash_b64}"

def fix_user_account():
    """Fix user accounts directly in the database"""
    if not DB_URL:
        print("ERROR: DATABASE_URL environment variable is not set.")
        print("Please set it to your PostgreSQL connection string.")
        return False
    
    print(f"Connecting to database...")
    
    # Try to use psycopg2 if available
    try:
        import psycopg2
        have_psycopg2 = True
        print("Using psycopg2 driver")
    except ImportError:
        have_psycopg2 = False
        print("psycopg2 not available, will try direct SQL")
    
    try:
        if have_psycopg2:
            # Connect to database using psycopg2
            conn = psycopg2.connect(DB_URL)
            cursor = conn.cursor()
            
            # Find existing users
            cursor.execute("SELECT id, username, email FROM users WHERE username IN ('admin', 'standard')")
            users = cursor.fetchall()
            
            if not users:
                print("WARNING: No users found with usernames 'admin' or 'standard'")
                return False
            
            # Generate password hash
            password_hash = generate_password_hash(NEW_PASSWORD)
            
            # Update each user
            for user in users:
                user_id, username, email = user
                
                print(f"User ID: {user_id}, Username: {username}")
                print(f"  Current email: {email or 'None'}")
                
                # Fix email field
                new_email = ADMIN_EMAIL if username == 'admin' else STANDARD_EMAIL
                
                # Update user record
                # password_hash field removed after schema cleanup (May 2025)
                cursor.execute(
                    "UPDATE users SET email = %s, hashed_password = %s WHERE id = %s",
                    (new_email, password_hash, user_id)
                )
                
                print(f"  Updated email to: {new_email}")
                print(f"  Reset password to: {NEW_PASSWORD}")
            
            # Commit changes
            conn.commit()
            print(f"Successfully updated {len(users)} user(s)")
            
            # Close cursor and connection
            cursor.close()
            conn.close()
        else:
            print("This method requires psycopg2. Please install it with:")
            print("pip install psycopg2-binary")
            return False
        
        return True
    except Exception as e:
        print(f"ERROR: {str(e)}")
        try:
            if have_psycopg2 and 'conn' in locals():
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