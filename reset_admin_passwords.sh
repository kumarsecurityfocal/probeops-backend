#!/bin/bash
# Script to reset admin and standard user passwords for ProbeOps API

# Set password
NEW_PASSWORD="probeopS1@"
echo "Resetting passwords to: $NEW_PASSWORD"

# Method 1: Direct database script
echo "Method 1: Using direct database access..."
python reset_passwords.py "$NEW_PASSWORD"

# Method 2: Using Flask CLI
echo -e "\nMethod 2: Using Flask CLI..."
export FLASK_APP=reset_passwords_flask.py
python -m flask reset-default-passwords

echo -e "\nPassword reset process complete."
echo "Try logging in with:"
echo "- Username: admin@probeops.com, Password: $NEW_PASSWORD"
echo "- Username: standard@probeops.com, Password: $NEW_PASSWORD"