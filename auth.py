# /home/nosameoj/Crypto/secure_file_transfer_system/auth.py

"""
Handles secure user registration and login functionality.

This module implements password hashing using Argon2, a modern, secure
key derivation function designed to be resistant to GPU cracking attacks.
"""

import os
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the password hasher with default recommended parameters
ph = PasswordHasher()

USER_DB_FILE = 'users.json'

def _load_users():
    """Loads the user database from the JSON file."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, 'r') as f:
        return json.load(f)

def _save_users(users):
    """Saves the user database to the JSON file."""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def register_user(username, password, role):
    """
    Registers a new user, hashes their password, and stores it.

    Args:
        username (str): The username for the new user.
        password (str): The user's plaintext password.
        role (str): The user's role (e.g., 'Clinician', 'Researcher', 'Auditor').

    Returns:
        bool: True if registration was successful, False otherwise.
    """
    users = _load_users()
    if username in users:
        print(f"Error: Username '{username}' already exists.")
        return False

    # Hash the password. Argon2 handles salt generation automatically.
    hashed_password = ph.hash(password)

    users[username] = {
        'hash': hashed_password,
        'role': role
    }
    _save_users(users)
    print(f"User '{username}' registered successfully as a '{role}'.")
    return True

def login_user(username, password):
    """
    Verifies a user's login credentials.

    Returns:
        str: The user's role if login is successful, None otherwise.
    """
    users = _load_users()
    if username not in users:
        return None

    try:
        # ph.verify checks the password and raises an exception if it fails.
        # This is resistant to timing attacks.
        ph.verify(users[username]['hash'], password)
        return users[username]['role']
    except VerifyMismatchError:
        return None