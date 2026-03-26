# /home/nosameoj/Crypto/secure_file_transfer_system/auth.py

"""
Handles secure user registration and login functionality.

This module implements password hashing using Argon2, a modern, secure
key derivation function designed to be resistant to GPU cracking attacks.
"""

import os
import json
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the password hasher with default recommended parameters
ph = PasswordHasher()

USER_DB_FILE = 'users.json'

def load_users():
    """Loads the user database from the JSON file."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {} # Return empty dict if file is empty or corrupt

def _save_users(users):
    """Saves the user database to the JSON file."""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def register_user(username, password, role, public_key):
    """
    Registers a new user, hashes their password, and stores it along with a TOTP secret.

    Args:
        username (str): The username for the new user.
        password (str): The user's plaintext password.
        role (str): The user's role (e.g., 'Clinician', 'Researcher', 'Auditor').
        public_key (str): The user's public key in PEM format.

    Returns:
        A tuple of (bool, str). (True, provisioning_uri) if registration was successful,
        (False, None) otherwise.
    """
    users = load_users()
    if username in users:
        print(f"Error: Username '{username}' already exists.")
        return False, None

    # Hash the password. Argon2 handles salt generation automatically.
    hashed_password = ph.hash(password)

    # Generate a TOTP secret for MFA
    totp_secret = pyotp.random_base32()
    provisioning_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=username, issuer_name='SecureClinicalDataSystem'
    )

    users[username] = {
        'hash': hashed_password,
        'role': role,
        'public_key': public_key,
        'totp_secret': totp_secret
    }
    _save_users(users)
    print(f"User '{username}' registered successfully as a '{role}'.")
    return True, provisioning_uri

def login_user(username, password):
    """
    Verifies a user's password.

    Returns:
        bool: True if password is correct, False otherwise.
    """
    users = load_users()
    if username not in users:
        return False

    try:
        # ph.verify checks the password and raises an exception if it fails.
        ph.verify(users[username]['hash'], password)
        return True
    except VerifyMismatchError:
        return False

def verify_mfa_code(username, mfa_code):
    """
    Verifies the MFA code for a given user.

    Returns:
        str: The user's role if the MFA code is valid, None otherwise.
    """
    users = load_users()
    user_data = users.get(username)
    if not user_data or 'totp_secret' not in user_data:
        return None

    totp = pyotp.TOTP(user_data['totp_secret'])
    if totp.verify(mfa_code):
        return user_data['role']
    return None