#!/bin/bash
# Script to list all tables in the production database

PGHOST="probeops-db.cj7djvax3zud.us-east-1.rds.amazonaws.com"
PGPORT=5432
PGUSER="postgres"
PGDATABASE="probeops"

echo "Listing all tables in production database..."
echo "==========================================="

# List all tables in the public schema
psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE -c "\dt"

echo ""
echo "Looking for user-related tables..."
echo "================================="

# Search for tables that might contain user information
psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE -c "\dt *user*"

echo ""
echo "Listing schemas..."
echo "=================="

# List all schemas
psql -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE -c "\dn"

echo ""
echo "If you don't see any tables related to users, your database schema might be different"
echo "or the tables might be in a different schema than 'public'."