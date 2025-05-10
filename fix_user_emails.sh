#!/bin/bash
# Script to fix missing email fields for ProbeOps API users

echo "Fixing missing email fields for admin and standard users..."

# Check which Python command is available
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "ERROR: Neither python3 nor python commands were found."
    echo "Please install Python or ensure it's in your PATH."
    exit 1
fi

echo "Using Python command: $PYTHON_CMD"

# Method 1: Direct database script
echo "Method 1: Using direct database access..."
$PYTHON_CMD fix_user_emails.py

# Method 2: Using Flask CLI
echo -e "\nMethod 2: Using Flask CLI..."
export FLASK_APP=fix_user_emails_flask.py
$PYTHON_CMD -m flask fix-user-emails

echo -e "\nUser email fix process complete."
echo "Try logging in with:"
echo "- Email: admin@probeops.com, Password: probeopS1@"
echo "- Email: standard@probeops.com, Password: probeopS1@"