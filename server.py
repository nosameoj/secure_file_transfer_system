# /home/nosameoj/Crypto/secure_file_transfer_system/server.py
# This python file runst eh back end of the server for the system
#flask is used to create a simple API that can be accessed through the terminal

import os
import uuid
import json
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename
from auth import login_user, register_user, verify_mfa_code, load_users
from validation import (is_valid_username, is_valid_password_length,
    is_valid_password_complexity, is_valid_role,
    is_valid_mfa_code, is_valid_public_key, is_valid_unique_filename)

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
FILE_METADATA_FILE = 'uploads/file_metadata.json'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
mfa_debug = True # if true MFA will accept any 6 digit code to allow access

def _load_file_metadata():
    #loading file_metadata from file_metadata.json
    if not os.path.exists(FILE_METADATA_FILE):
        return {}
    with open(FILE_METADATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def _save_file_metadata(metadata):
    #saves file metadata to "file_metadate.josn"
    # make sure dir exists before modification
    os.makedirs(os.path.dirname(FILE_METADATA_FILE), exist_ok=True)
    with open(FILE_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=4)

@app.route('/login', methods=['POST'])
def login():

    # handles the first step of login: password verification.
    # expects a JSON payload with 'username' and 'password'.

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    valid, msg = is_valid_username(username)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_password_length(password)
    if not valid:
        return jsonify({'message': msg}), 400

    if login_user(username, password):
        return jsonify({'message': 'Password correct. Please provide MFA code.', 'mfa_required': True}), 200
    else:
        return jsonify({'message': 'Invalid username or password.'}), 401

@app.route('/login/verify-mfa', methods=['POST'])
def login_verify_mfa():

    # Handles the second step of login: MFA code verification.
    # Expects 'username' and 'mfa_code'.

    data = request.get_json()
    username = data.get('username')
    mfa_code = data.get('mfa_code')

    valid, msg = is_valid_username(username)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_mfa_code(mfa_code)
    if not valid:
        return jsonify({'message': msg}), 400

    role = verify_mfa_code(username, mfa_code)
    if role: #returns successful MFA response 
        return jsonify({'message': f'Login successful. Welcome {username}.', 'role': role}), 200
    elif mfa_debug == True: # allows login with incorrect MFA code for debugging reasons
        return jsonify({'message': f'Login successful through debug. Welcome {username}.', 'role': role}), 200
    else:
        return jsonify({'message': 'Invalid MFA code.'}), 401


@app.route('/register', methods=['POST'])
def register():

    # expects a JSON payload with 'username', 'password', 'role', and 'public_key', and creates a user from that info
  
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    public_key = data.get('public_key')

    valid, msg = is_valid_username(username)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_password_length(password)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_password_complexity(password)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_role(role)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_public_key(public_key)
    if not valid:
        return jsonify({'message': msg}), 400

    success, provisioning_uri = register_user(username, password, role, public_key)
    if not success:
        return jsonify({'message': 'Registration failed. Username might already exist.'}), 400

    return jsonify({'message': 'Registration successful.', 'provisioning_uri': provisioning_uri}), 201

@app.route('/upload', methods=['POST'])
def upload_file():
    #handles file uploads for the system, expects a file, key ring loop, allowed roles, role and username of uploader.
    # also ensures that all parts uploaded are valid
    # # --- validation ---
    #make sure a file has been uploaded, and all variables are valid for their data type
    if 'file' not in request.files:
        return jsonify({'message': 'No file part in the request'}), 400
    file = request.files['file']

    # If the user does not select a file, the browser submits an
    # empty part without a filename.
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    username = request.form.get('username')
    role = request.form.get('role')
    allowed_roles_str = request.form.get('allowed_roles')
    key_ring_loop_str = request.form.get('key_ring_loop')

    valid, msg = is_valid_username(username)
    if not valid:
        return jsonify({'message': msg}), 400

    valid, msg = is_valid_role(role)
    if not valid:
        return jsonify({'message': msg}), 400

    if not allowed_roles_str or not key_ring_loop_str:
        return jsonify({'message': 'Allowed roles and key ring are required.'}), 400

    try:
        key_ring_loop = json.loads(key_ring_loop_str)
        allowed_roles = [r.strip() for r in allowed_roles_str.split(',') if r.strip()]
    except json.JSONDecodeError:
        return jsonify({'message': 'Invalid key ring format.'}), 400

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
            'allowed_roles': allowed_roles,
            'key_ring_loop': key_ring_loop
        }
        _save_file_metadata(metadata)
        print(f"File '{original_filename}' (saved as '{unique_filename}') uploaded by user '{username}' with role '{role}'.")
        return jsonify({'message': f'File "{original_filename}" uploaded successfully.'}), 200

    return jsonify({'message': 'File upload failed.'}), 400

@app.route('/files', methods=['GET'])
def list_files():
  
    #lists files that are accessible to the user based on their role being in the 'allowed_roles' list.
 
    user_role = request.args.get('role')
    valid, msg = is_valid_role(user_role)
    if not valid:
        return jsonify({'message': msg}), 400

    metadata = _load_file_metadata()
    accessible_files = []
    for unique_filename, file_data in metadata.items():
        #access is allowed if the users role is in the allowed roles for the file
        if user_role in file_data.get('allowed_roles', []):
            accessible_files.append({
                'unique_filename': unique_filename,
                'original_filename': file_data.get('original_filename', 'N/A'),
                'uploader': file_data.get('uploader', 'N/A'),
                'timestamp': file_data.get('upload_timestamp', 'N/A'),
                'key_ring_loop': file_data.get('key_ring_loop', {})
            })
    return jsonify(accessible_files), 200

@app.route('/download/<string:unique_filename>', methods=['POST'])
def download_file(unique_filename):
   #handles the downloading of files from the system, making sure that downloadable files are specific to the user role
    valid, msg = is_valid_unique_filename(unique_filename)
    if not valid:
        return jsonify({'message': msg}), 400

    data = request.get_json()
    role = data.get('role')

    valid, msg = is_valid_role(role)
    if not valid:
        return jsonify({'message': msg}), 400

    metadata = _load_file_metadata()
    file_metadata = metadata.get(unique_filename)

    if not file_metadata:
        return jsonify({'message': 'File not found.'}), 404

    #access is granted if the users role is in the files list of allowed roles
    if role not in file_metadata.get('allowed_roles', []):
        return jsonify({'message': 'Access denied. You do not have the required role.'}), 403

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        unique_filename,
        as_attachment=True,
        download_name=file_metadata.get('original_filename') #encrpyted file
    )

@app.route('/public-keys', methods=['GET'])
def get_public_keys():

    # retrieves and returns all public keys of the same user role as the uploader
    # expects a .csv with all the data
    # e.g., /public-keys?roles=Clinician,Researcher

    roles_str = request.args.get('roles')
    if not roles_str:
        return jsonify({'message': 'Roles query parameter is required.'}), 400
    
    target_roles = set(r.strip() for r in roles_str.split(','))
    users = load_users()
    keys = {username: data['public_key'] for username, data in users.items() if data.get('role') in target_roles}

    return jsonify(keys), 200

if __name__ == '__main__':
    app.run(port=5000)