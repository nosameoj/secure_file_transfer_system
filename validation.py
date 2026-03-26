# /home/nosameoj/Crypto/secure_file_transfer_system/validation.py

"""
This module provides centralized input validation functions for the server.
"""

import re

# Define constraints
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3
MAX_PASSWORD_LENGTH = 256 # For DoS prevention
MIN_PASSWORD_LENGTH = 1
MFA_CODE_LENGTH = 6
ALLOWED_ROLES = ['Clinician', 'Researcher', 'Auditor', 'Admin']

# Regex patterns
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")
MFA_CODE_REGEX = re.compile(r"^\d{6}$")
PUBLIC_KEY_REGEX = re.compile(r"-----BEGIN PUBLIC KEY-----(.|\n)+-----END PUBLIC KEY-----")
UUID_REGEX = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}_")

def is_valid_username(username):
    if not username: return False, "Username cannot be empty."
    if not (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH):
        return False, f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters."
    if not USERNAME_REGEX.match(username):
        return False, "Username can only contain letters, numbers, underscores, and dashes."
    return True, "Username is valid."

def is_valid_password_length(password):
    if not password: return False, "Password cannot be empty."
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return False, f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters."
    return True, "Password length is valid."

def is_valid_password_complexity(password):
    """Checks if the password meets complexity requirements."""
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if all(c.isalnum() for c in password):
        return False, "Password must contain at least one special character."
    return True, "Password meets complexity requirements."

def is_valid_role(role):
    if role not in ALLOWED_ROLES:
        return False, f"Invalid role. Must be one of {ALLOWED_ROLES}."
    return True, "Role is valid."

def is_valid_mfa_code(mfa_code):
    if not mfa_code or not MFA_CODE_REGEX.match(mfa_code):
        return False, f"MFA code must be {MFA_CODE_LENGTH} digits."
    return True, "MFA code is valid."

def is_valid_public_key(public_key):
    if not public_key or not PUBLIC_KEY_REGEX.search(public_key):
        return False, "Public key must be in a valid PEM format."
    return True, "Public key is valid."

def is_valid_unique_filename(filename):
    if not filename or not UUID_REGEX.match(filename):
        return False, "Invalid file identifier format."
    return True, "Filename format is valid."
