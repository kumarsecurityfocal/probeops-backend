#!/bin/bash
# Script to fix missing email fields for ProbeOps API users

echo "Fixing missing email fields for admin and standard users..."

# Method 1: Direct database script
echo "Method 1: Using direct database access..."
python fix_user_emails.py

# Method 2: Using Flask CLI
echo -e "\nMethod 2: Using Flask CLI..."
export FLASK_APP=fix_user_emails_flask.py
python -m flask fix-user-emails

echo -e "\nUser email fix process complete."
echo "Try logging in with:"
echo "- Email: admin@probeops.com, Password: probeopS1@"
echo "- Email: standard@probeops.com, Password: probeopS1@"