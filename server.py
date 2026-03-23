# /home/nosameoj/Crypto/secure_file_transfer_system/server.py

"""
This script runs the backend server for the secure communication system.
It uses Flask to create a simple API that clients can interact with.
"""

from flask import Flask, jsonify, request
from auth import login_user, register_user

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login requests.
    Expects a JSON payload with 'username' and 'password'.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    role = login_user(username, password)

    if role:
        return jsonify({'message': f'Login successful. Welcome {username}.', 'role': role}), 200
    else:
        return jsonify({'message': 'Invalid username or password.'}), 401


@app.route('/register', methods=['POST'])
def register():
    """
    Handles user registration requests.
    Expects a JSON payload with 'username', 'password', and 'role'.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not register_user(username, password, role):
        return jsonify({'message': 'Registration failed.'}), 400

    return jsonify({'message': 'Registration successful.'}), 201



if __name__ == '__main__':
    # Note: debug=True is for development only.
    app.run(port=5000, debug=True)