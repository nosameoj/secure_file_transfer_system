# /home/nosameoj/Crypto/secure_file_transfer_system/auth.py

#this module handles secure user authentication and registration workflows
#it implements password hashing using argon2, a modern and highly secure
#key derivation function that leverages memory-hardness to provide
#substantial cryptographic resistance against parallelized gpu cracking attacks

import os
import json
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

#initializes the argon2 password hasher using current recommended parameters
#this configuration balances computational cost with adequate security margins
#against offline brute-force attempts while maintaining application responsiveness
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
    #registers a new entity within the local authentication database
    #cryptographically hashes their password, and instantiates a unique
    #time-based one-time password secret to establish a robust multi-factor
    #authentication baseline for the system architecture
    users = load_users()
    if username in users:
        print(f"Error: Username '{username}' already exists.")
        return False, None

    #derives a secure, computationally expensive hash from the plaintext password
    #argon2 transparently handles the generation of a unique cryptographic salt
    #protecting the resulting key material against pre-computed rainbow table attacks
    hashed_password = ph.hash(password)

    #generates a base32 encoded random secret for the totp generation algorithm
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
    #authenticates a given session by cross-referencing the submitted plaintext
    #password against the persistently stored, salted argon2 representation
    users = load_users()
    if username not in users:
        return False

    try:
        #executes the constant-time verification algorithm provided by argon2
        #mitigating side-channel timing attacks that might leak password validity
        ph.verify(users[username]['hash'], password)
        return True
    except VerifyMismatchError:
        return False

def verify_mfa_code(username, mfa_code):
    #validates the multi-factor authentication token utilizing the totp standard
    #providing an indispensable supplementary layer of identity verification
    #independent of the primary password-based authentication mechanism
    users = load_users()
    user_data = users.get(username)
    if not user_data or 'totp_secret' not in user_data:
        return None

    totp = pyotp.TOTP(user_data['totp_secret'])
    if totp.verify(mfa_code):
        return user_data['role']
    return None