#!/bin/bash
# Script to reset admin and standard user passwords for ProbeOps API

# Set password
NEW_PASSWORD="probeopS1@"
echo "Resetting passwords to: $NEW_PASSWORD"

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
$PYTHON_CMD reset_passwords.py "$NEW_PASSWORD"

# Method 2: Using Flask CLI
echo -e "\nMethod 2: Using Flask CLI..."
export FLASK_APP=reset_passwords_flask.py
$PYTHON_CMD -m flask reset-default-passwords

echo -e "\nPassword reset process complete."
echo "Try logging in with:"
echo "- Username: admin@probeops.com, Password: $NEW_PASSWORD"
echo "- Username: standard@probeops.com, Password: $NEW_PASSWORD"