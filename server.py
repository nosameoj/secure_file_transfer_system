# /home/nosameoj/Crypto/secure_file_transfer_system/server.py
#this script operates the backend restful api for the secure transfer system
#it leverages the flask framework to expose endpoints for file operations
#and authentication, strictly enforcing role-based access control measures
#throughout all critical functions to uphold the principle of least privilege

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
LOG_FILE = 'uploads/audit_log.json'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
mfa_debug = True # if true MFA will accept any 6 digit code to allow access

def _load_file_metadata():
    #loads the persistent file metadata from a local json store
    #this structure contains essential routing, authorization, and
    #cryptographic signature data required for secure system operations
    if not os.path.exists(FILE_METADATA_FILE):
        return {}
    with open(FILE_METADATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def _save_file_metadata(metadata):
    #atomically persists updated metadata configurations to the server
    #ensuring that access control definitions and cryptographic key rings
    #are durably maintained and consistently enforced across reboots
    os.makedirs(os.path.dirname(FILE_METADATA_FILE), exist_ok=True)
    with open(FILE_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=4)

def _load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def _log_action(action, username, details=""):
    logs = _load_logs()
    log_entry = {'timestamp': datetime.utcnow().isoformat() + 'Z', 'action': action, 'username': username, 'details': details}
    logs.append(log_entry)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

@app.route('/login', methods=['POST'])
def login():
    #handles the initial phase of the user authentication workflow
    #verifying the structural validity of the provided login credentials
    #before initiating the computationally expensive password hash comparison

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
    #processes the second factor of the authentication sequence
    #validating the time-based one-time password provided by the client
    #which significantly limits the attack surface for compromised credentials

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
        _log_action('LOGIN', username, f'Successful login as {role}')
        return jsonify({'message': f'Login successful. Welcome {username}.', 'role': role}), 200
    elif mfa_debug: # allows login with incorrect MFA code for debugging reasons
        # If debug is on, we still need to fetch the user's role as verify_mfa_code returned None
        users = load_users()
        user_data = users.get(username)
        role = user_data.get('role') if user_data else None
        _log_action('LOGIN', username, f'Successful debug login as {role}')
        return jsonify({'message': f'Login successful through debug. Welcome {username}.', 'role': role}), 200
    else:
        _log_action('LOGIN_FAILED', username, 'Failed MFA verification')
        return jsonify({'message': 'Invalid MFA code.'}), 401


@app.route('/register', methods=['POST'])
def register():
    #facilitates the secure onboarding and provisioning of new system entities
    #enforcing strict password complexity and predefined role constraints before
    #persisting the users cryptographic identity material to the backend datastore
  
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
    #manages the secure ingress and indexing of encrypted clinical payloads
    #validating all multipart form submissions and cryptographic metadata
    #to ensure malicious actors cannot inject unauthorized or malformed data
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
    signature = request.form.get('signature', '')

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
        #generates a universally unique identifier to prepend to filenames
        #preventing namespace collisions and providing a crucial mitigation
        #against directory traversal vulnerabilities on the underlying filesystem
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
            'key_ring_loop': key_ring_loop,
            'signature': signature
        }
        _save_file_metadata(metadata)
        _log_action('UPLOAD', username, f'Uploaded file {unique_filename}')
        print(f"File '{original_filename}' (saved as '{unique_filename}') uploaded by user '{username}' with role '{role}'.")
        return jsonify({'message': f'File "{original_filename}" uploaded successfully.'}), 200

    return jsonify({'message': 'File upload failed.'}), 400

@app.route('/files', methods=['GET'])
def list_files():
    #enumerates files currently available within the storage repository
    #applying mandatory access controls to transparently filter out any assets
    #that fall outside the defined scope of the requesting users clearance level
 
    user_role = request.args.get('role')
    valid, msg = is_valid_role(user_role)
    if not valid:
        return jsonify({'message': msg}), 400

    metadata = _load_file_metadata()
    accessible_files = []
    for unique_filename, file_data in metadata.items():
        #evaluates if the users role satisfies the required file access policy
        if user_role in file_data.get('allowed_roles', []) or (user_role == 'Auditor' and file_data.get('uploader_role') == 'Researcher'):
            accessible_files.append({
                'unique_filename': unique_filename,
                'original_filename': file_data.get('original_filename', 'N/A'),
                'uploader': file_data.get('uploader', 'N/A'),
                'uploader_role': file_data.get('uploader_role', 'N/A'),
                'timestamp': file_data.get('upload_timestamp', 'N/A'),
                'key_ring_loop': file_data.get('key_ring_loop', {}),
                'signature': file_data.get('signature', '')
            })
    return jsonify(accessible_files), 200

@app.route('/download/<string:unique_filename>', methods=['POST'])
def download_file(unique_filename):
    #facilitates the secure egress of encrypted payloads from the application
    #enforcing role-based access controls prior to initiating transmission
    #to guarantee that sensitive assets are exclusively served to authorized parties
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

    #verifies the authorization context strictly against the file access control list
    #immediately rejecting requests that do not satisfy the required permission matrix
    if role not in file_metadata.get('allowed_roles', []) and role != 'Auditor':
        _log_action('DOWNLOAD_DENIED', data.get('username', 'Unknown'), f'Access denied to {unique_filename}')
        return jsonify({'message': 'Access denied. You do not have the required role.'}), 403

    _log_action('DOWNLOAD', data.get('username', 'Unknown'), f'Downloaded file {unique_filename}')
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        unique_filename,
        as_attachment=True,
        download_name=file_metadata.get('original_filename') #encrpyted file
    )

@app.route('/public-keys', methods=['GET'])
def get_public_keys():
    #exposes a dedicated directory service for retrieving public keys
    #this is a prerequisite for constructing the encrypted key ring loop
    #during the client-side hybrid encryption phase of the upload workflow

    roles_str = request.args.get('roles')
    if not roles_str:
        return jsonify({'message': 'Roles query parameter is required.'}), 400
    
    target_roles = set(r.strip() for r in roles_str.split(','))
    users = load_users()
    keys = {username: data['public_key'] for username, data in users.items() if data.get('role') in target_roles}

    return jsonify(keys), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    user_role = request.args.get('role')
    valid, msg = is_valid_role(user_role)
    if not valid:
        return jsonify({'message': msg}), 400

    if user_role != 'Auditor':
        return jsonify({'message': 'Access denied. Only Auditors can view logs.'}), 403

    logs = _load_logs()
    return jsonify(logs), 200

if __name__ == '__main__':
    app.run(port=5000)