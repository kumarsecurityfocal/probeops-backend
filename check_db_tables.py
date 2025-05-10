#!/usr/bin/env python3
"""
Simple script to check the database structure in ProbeOps API
"""
import os
import sys

# Get database URL from environment
DB_URL = os.environ.get('DATABASE_URL')

def check_database():
    """List all tables in the database"""
    if not DB_URL:
        print("ERROR: DATABASE_URL environment variable is not set.")
        print("Please set it to your PostgreSQL connection string.")
        return False
    
    print(f"Connecting to database...")
    
    try:
        import psycopg2
        have_psycopg2 = True
        print("Using psycopg2 driver")
    except ImportError:
        have_psycopg2 = False
        print("psycopg2 not available, please install it")
        return False
    
    try:
        # Connect to database
        conn = psycopg2.connect(DB_URL)
        cursor = conn.cursor()
        
        # Get all tables in the database
        print("\nListing all tables in the database:")
        cursor.execute("""
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name
        """)
        
        tables = cursor.fetchall()
        
        if not tables:
            print("No tables found in the database!")
            return False
        
        for schema, table in tables:
            print(f"- {schema}.{table}")
            
            # List columns for each table
            cursor.execute("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position
            """, (schema, table))
            
            columns = cursor.fetchall()
            for column_name, data_type, is_nullable in columns:
                nullable = "NULL" if is_nullable == 'YES' else "NOT NULL"
                print(f"  - {column_name} ({data_type}, {nullable})")
            print()
        
        # Look specifically for user tables
        print("\nSearching for tables related to users:")
        cursor.execute("""
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_name ILIKE '%user%' AND
                  table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name
        """)
        
        user_tables = cursor.fetchall()
        if not user_tables:
            print("No tables found with 'user' in the name!")
        else:
            for schema, table in user_tables:
                print(f"- {schema}.{table}")
        
        # Close cursor and connection
        cursor.close()
        conn.close()
        
        return True
    
    except Exception as e:
        print(f"ERROR: {str(e)}")
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass
        return False

if __name__ == "__main__":
    print(f"Starting database check...")
    
    if not check_database():
        print("\nFailed to check database. See error messages above.")
        sys.exit(1)
    
    print("\nDatabase check complete!")