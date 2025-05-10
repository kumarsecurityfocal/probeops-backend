#!/usr/bin/env python
"""
Check user roles in the production database.
Run this script on your production server to verify user roles.
"""
import os
import sys
import psycopg2
from psycopg2.extras import DictCursor

def check_user_roles(emails):
    """Check roles for specific email addresses in the production database."""
    # Use production database URL from environment variable
    db_url = os.environ.get("DATABASE_URL")
    
    if not db_url:
        print("Error: DATABASE_URL environment variable not set.")
        sys.exit(1)
    
    try:
        # Connect to the production database
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Build query for multiple emails
        email_placeholders = ','.join(['%s'] * len(emails))
        query = f"""
            SELECT id, username, email, role, subscription_tier 
            FROM users 
            WHERE email IN ({email_placeholders})
        """
        
        # Execute query
        cursor.execute(query, emails)
        users = cursor.fetchall()
        
        # Display results
        if not users:
            print("No users found with the specified email addresses.")
        else:
            print(f"{'ID':<5} {'Username':<15} {'Email':<30} {'Role':<10} {'Subscription Tier':<15}")
            print("-" * 80)
            for user in users:
                print(f"{user['id']:<5} {user['username']:<15} {user['email']:<30} "
                      f"{user['role']:<10} {user['subscription_tier']:<15}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check roles for standard and admin users
    check_user_roles(['standard@probeops.com', 'admin@probeops.com'])