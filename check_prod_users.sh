#!/bin/bash
# Script to check user roles in production database
# Make this file executable with: chmod +x check_prod_users.sh

echo "Checking user roles in production database..."

# Check if psql command is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql command not found. Please make sure PostgreSQL client is installed."
    exit 1
fi

# Check if DATABASE_URL environment variable is set
if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL environment variable not set."
    echo "Please set it first: export DATABASE_URL=postgresql://username:password@host:port/database"
    exit 1
fi

# Run the query
echo "User roles in production database:"
echo "=================================="
psql "$DATABASE_URL" -c "SELECT id, username, email, role, subscription_tier FROM users WHERE email IN ('standard@probeops.com', 'admin@probeops.com');"

# Check if the command succeeded
if [ $? -ne 0 ]; then
    echo "Error executing SQL query. Please check your database connection."
    exit 1
fi

echo ""
echo "If no users are shown above, it means these email addresses do not exist in your production database."