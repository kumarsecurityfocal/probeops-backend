from werkzeug.security import generate_password_hash, check_password_hash

# Generate a new password hash
password = "testpass123"
hash = generate_password_hash(password)
print(f"Generated hash for '{password}': {hash}")

# Test checking the password
correct = check_password_hash(hash, password)
incorrect = check_password_hash(hash, "wrongpassword")

print(f"Correct password check result: {correct}")
print(f"Incorrect password check result: {incorrect}")