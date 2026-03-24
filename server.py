# /home/nosameoj/Crypto/secure_file_transfer_system/server.py

"""
This script runs the backend server for the secure communication system.
It uses Flask to create a simple API that clients can interact with.
"""

import os
import uuid
import json
from datetime import datetime
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename
from auth import login_user, register_user

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
FILE_METADATA_FILE = 'uploads/file_metadata.json'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def _load_file_metadata():
    """Loads the file metadata from the JSON file."""
    if not os.path.exists(FILE_METADATA_FILE):
        return {}
    with open(FILE_METADATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def _save_file_metadata(metadata):
    """Saves the file metadata to the JSON file."""
    with open(FILE_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=4)

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
    Expects a JSON payload with 'username', 'password', 'role', and 'public_key'.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    public_key = data.get('public_key')

    if not all([username, password, role, public_key]):
        return jsonify({'message': 'Username, password, role, and public_key are required.'}), 400

    if not register_user(username, password, role, public_key):
        return jsonify({'message': 'Registration failed. Username might already exist.'}), 400

    return jsonify({'message': 'Registration successful.'}), 201

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handles file uploads.
    Expects a multipart/form-data request with a 'file' part,
    and 'username' and 'role' as form fields.
    NOTE: In a real-world application, user authentication should be handled
    via tokens (e.g., JWT) instead of passing username/role in the form.
    """
    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'message': 'No file part in the request'}), 400
    file = request.files['file']

    # If the user does not select a file, the browser submits an
    # empty part without a filename.
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    username = request.form.get('username')
    role = request.form.get('role')

    if not username or not role:
        return jsonify({'message': 'Username and role are required as form fields.'}), 400

    if file:
        original_filename = secure_filename(file.filename)
        # Generate a unique filename to prevent overwrites and link to metadata
        unique_filename = f"{uuid.uuid4()}_{original_filename}"

        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

        # Load metadata, update it, and save it back
        metadata = _load_file_metadata()
        metadata[unique_filename] = {
            'original_filename': original_filename,
            'uploader': username,
            'uploader_role': role,
            'upload_timestamp': datetime.utcnow().isoformat() + 'Z',
            'key_ring_loop': {} # Placeholder for future key management
        }
        _save_file_metadata(metadata)
        print(f"File '{original_filename}' (saved as '{unique_filename}') uploaded by user '{username}' with role '{role}'.")
        return jsonify({'message': f'File "{original_filename}" uploaded successfully.'}), 200

    return jsonify({'message': 'File upload failed.'}), 400
if __name__ == '__main__':
    # Note: debug=True is for development only.
    app.run(port=5000, debug=True)