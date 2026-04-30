# /home/nosameoj/Crypto/secure_file_transfer_system/client.py

#this script operates the client-side of the secure file transfer system
#implementing hybrid cryptographic techniques and multi-factor authentication
#to ensure confidentiality, integrity, and authenticity of clinical data

import requests
import getpass
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import qrcode
import sys
import re
import select
import json
import base64

SERVER_URL = 'http://127.0.0.1:5000'
login_attempts = 0
TIMEOUT_SECONDS = 60 # 1 minute
# Client-side validation constraints
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MFA_CODE_LENGTH = 6
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")
MFA_CODE_REGEX = re.compile(r"^\d{6}$")


def input_with_timeout(prompt, timeout=TIMEOUT_SECONDS):
    """
    Gets user input with a timeout.
    Supports both Unix-like systems and Windows.

    Returns:
        The input string, or None if the timeout is reached.
    """
    #gathers user input while enforcing a strict inactivity timeout
    #this addresses critical session management security requirements
    #by mitigating risks of unauthorized access on unattended terminals

    print(prompt, end=' ', flush=True)
    if os.name == 'nt': #handling windows clients, written and tested on linux
        import msvcrt
        import time
        start_time = time.time()
        input_string = ""
        while True:
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char in ('\x00', '\xe0'):
                    msvcrt.getwch() #consume scan code for special keys like arrows
                    continue
                if char == '\x03': # ctrl c support
                    raise KeyboardInterrupt
                if char in ('\r', '\n'):
                    print()
                    return input_string.strip()
                elif char == '\x08': #backspace support
                    if len(input_string) > 0:
                        input_string = input_string[:-1]
                        print('\b \b', end='', flush=True)
                else:
                    input_string += char
                    print(char, end='', flush=True)
            if time.time() - start_time > timeout:
                print("\n\n[!] Timed out due to inactivity. You have been logged out.")
                return None
            time.sleep(0.01)
    else:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            return sys.stdin.readline().strip()
        else:
            print("\n\n[!] Timed out due to inactivity. You have been logged out.")
            return None

def generate_and_save_keys(username, password):

    #generates a 2048-bit rsa key pair for asymmetric cryptography
    #the private key is encrypted at rest using scrypt and aes-128-cbc
    #ensuring that even if the host file system is compromised
    #the key remains secure provided the password has sufficient entropy

    key = RSA.generate(2048)
    public_key = key.publickey()

    keys_dir = 'client_keys'
    os.makedirs(keys_dir, exist_ok=True)

    #export and securely persist the encrypted private key to disk
    with open(os.path.join(keys_dir, f"{username}_private_key.pem"), 'wb') as f:
        f.write(key.export_key(format='PEM', passphrase=password, pkcs=8, protection='scryptAndAES128-CBC'))

    #export and persist the public key in standard pem format
    pem_public = public_key.export_key(format='PEM')
    with open(os.path.join(keys_dir, f'{username}_public_key.pem'), 'wb') as f:
        f.write(pem_public)

    print(f"Key pair generated and saved in '{keys_dir}'")
    return pem_public.decode('utf-8')

def load_private_key(username, password):
    """Loads and decrypts the user's private key from a local file."""
    key_path = os.path.join('client_keys', f"{username}_private_key.pem")
    if not os.path.exists(key_path):
        print("Private key file not found.")
        return None
    
    try:
        with open(key_path, 'r') as f:
            private_key = RSA.import_key(f.read(), passphrase=password)
        return private_key
    except (ValueError, TypeError) as e:
        # ValueError is raised for incorrect passphrase in pycryptodome
        print(f"Failed to decrypt private key. Incorrect password or corrupted key file.")
        return None

def view_logs(username, role):
    print("\nFetching audit logs...")
    try:
        response = requests.get(f"{SERVER_URL}/logs", params={'role': role, 'username': username})
        if response.status_code == 200:
            logs = response.json()
            if not logs:
                print("No logs found.")
                return
            print("\n--- Audit Logs ---")
            for log in logs:
                print(f"[{log.get('timestamp')}] {log.get('username')} - {log.get('action')}: {log.get('details')}")
            print("------------------")
        else:
            print(f"Failed to fetch logs: {response.json().get('message')}")
    except requests.exceptions.RequestException as e:
        print(f"A network error occurred: {e}")

def list_and_download_files(username, role):
    """
    Fetches the list of downloadable files from the server,
    prompts the user to select one, and downloads it.
    """
    print("\nFetching list of available files...")
    try:
        list_response = requests.get(f"{SERVER_URL}/files", params={'role': role})
        if list_response.status_code != 200:
            print(f"Error fetching file list: {list_response.json().get('message')}")
            return

        files = list_response.json()
        if not files:
            print("No files available for you to download with your current role.")
            return

        #presents the user with a sanitized list of authorized files
        #enforcing role-based visibility rules defined by the backend
        print("\n--- Files Available for Download ---")
        for i, file_info in enumerate(files):
            print(f"{i + 1}: {file_info['original_filename']} (Uploaded by: {file_info['uploader']})")
        print("------------------------------------")

        while True:
            try:
                choice_str = input_with_timeout(f"Enter the number of the file to download (1-{len(files)}), or 0 to cancel:")
                if choice_str is None:
                    return # Timeout occurred
                choice = int(choice_str)
                if 0 <= choice <= len(files):
                    break
                else:
                    print("Invalid number. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        if choice == 0:
            print("Download cancelled.")
            return

        selected_file = files[choice - 1]
        unique_filename = selected_file['unique_filename']
        original_filename = selected_file['original_filename']

        print(f"\nDownloading encrypted file '{original_filename}'...")
        download_response = requests.post(f"{SERVER_URL}/download/{unique_filename}", json={'username': username, 'role': role})

        if download_response.status_code == 200:
            #this process verifies the cryptographic signature attached to the file
            #utilizing the rsa-pss algorithm and a sha-256 digest to validate
            #the integrity and non-repudiation of the clinical data payload
            if role in ['Researcher', 'Auditor']:
                signature_b64 = selected_file.get('signature')
                uploader_username = selected_file.get('uploader')
                uploader_role = selected_file.get('uploader_role')
                
                if signature_b64 and uploader_username and uploader_role:
                    print("\nVerifying digital signature...")
                    keys_response = requests.get(f"{SERVER_URL}/public-keys", params={'roles': uploader_role})
                    if keys_response.status_code == 200:
                        public_keys = keys_response.json()
                        uploader_pub_key_pem = public_keys.get(uploader_username)
                        if uploader_pub_key_pem:
                            uploader_pub_key = RSA.import_key(uploader_pub_key_pem)
                            h = SHA256.new(download_response.content)
                            verifier = pss.new(uploader_pub_key)
                            try:
                                verifier.verify(h, base64.b64decode(signature_b64))
                                print("Digital signature verified successfully. File integrity intact.")
                            except (ValueError, TypeError):
                                print("Warning: Digital signature verification failed! The file may have been tampered with.")
                                proceed = input("Do you still want to proceed with decryption? (y/N): ")
                                if proceed.lower() != 'y':
                                    return
                            except Exception as e:
                                print(f"Warning: Digital signature verification encountered an error: {e}")
                                proceed = input("Do you still want to proceed with decryption? (y/N): ")
                                if proceed.lower() != 'y':
                                    return
                        else:
                            print("Warning: Could not find uploader's public key for verification.")
                    else:
                        print("Warning: Failed to fetch public keys for verification.")

            #initiates the hybrid decryption workflow to retrieve the plaintext
            #the symmetric aes key is first decrypted using the receivers rsa key
            #subsequently the aes key decrypts the bulk gcm ciphertext payload

            if role == 'Auditor':
                #print("auditor")
                return
            print("File downloaded. Enter your password to decrypt your private key for file decryption.")
            password = getpass.getpass("Password: ")
            private_key = load_private_key(username, password)
            if not private_key:
                return # Failed to load private key

            #extract the ciphered symmetric key specific to this user from
            #the cryptographic key ring attached to the file metadata
            key_ring = selected_file['key_ring_loop']
            encrypted_aes_key_b64 = key_ring.get(username)
            if not encrypted_aes_key_b64:
                print("Error: Could not find an encryption key for your user in the file's metadata.")
                return
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            
            #decrypt the encapsulated symmetric key utilizing rsa-oaep padding
            #which provides semantic security against chosen-ciphertext attacks
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            #authenticate and decrypt the payload utilizing aes in gcm mode
            #validating the authentication tag to detect any tampering in transit
            nonce = download_response.content[:16]
            tag = download_response.content[16:32]
            ciphertext = download_response.content[32:]
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            save_dir = 'downloads'
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, original_filename)
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"File decrypted and saved successfully to '{save_path}'")
        else:
            print(f"Failed to download file: {download_response.json().get('message')}")

    except requests.exceptions.RequestException as e:
        print(f"A network error occurred: {e}")

def main():
    global login_attempts
    """Main function to run the client application."""
    print("--- Secure Clinical Data Sharing System ---")


    while True:
        username = input("Enter username: ")
        if not (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH):
            print(f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters.")
        elif not USERNAME_REGEX.match(username):
            print("Username can only contain letters, numbers, underscores, and dashes.")
        else:
            break
    password = getpass.getpass("Enter password: ")

    # Step 1: Attempt to log in with password
    response = requests.post(f"{SERVER_URL}/login", json={'username': username, 'password': password})

    # Step 2: If password is correct, handle MFA
    if response.status_code == 200 and response.json().get('mfa_required'):
        while True:
            mfa_code = input("Enter your 6-digit authentication code: ")
            if MFA_CODE_REGEX.match(mfa_code):
                break
            else:
                print(f"Invalid format. Please enter exactly {MFA_CODE_LENGTH} digits.")
        mfa_response = requests.post(f"{SERVER_URL}/login/verify-mfa", json={'username': username, 'mfa_code': mfa_code})

        if mfa_response.status_code != 200:
            print(f"\n--- Server Response ---\n{mfa_response.json()['message']}\n-----------------------\n")
            main()
            return

        # Login successful!
        print(mfa_response.json()['message'])
        role = mfa_response.json()['role']
        print("Your role is:", role)

        if role == 'Auditor':
            log_choice = input_with_timeout("Do you want to view the audit logs? (y/N):")
            if log_choice is None:
                return # Timeout occurred, end session
            if log_choice.lower() == 'y':
                view_logs(username, role)

        # Post-login actions
        if role in ['Clinician', 'Researcher']:
            choice = input_with_timeout("Do you want to upload a file? (y/N):")
            if choice is None:
                return # Timeout occurred, end session
        else:
            choice = 'n'


        if choice.lower() == 'y':
            root = Tk()
            root.withdraw()
            print("Opening file browser to select a file...")
            filepath = askopenfilename()
            root.destroy()

            if filepath: # A file was selected

                # Get public keys for these roles
                print("Fetching public keys for allowed roles...")
                keys_response = requests.get(f"{SERVER_URL}/public-keys", params={'roles': role})
                if keys_response.status_code != 200:
                    print(f"Error fetching public keys: {keys_response.json().get('message')}")
                    return
                
                public_keys = keys_response.json()
                if not public_keys:
                    print("No users found for the specified roles. Cannot create key ring.")
                    return

                #implements a hybrid encryption architecture suitable for robust data sharing
                #a symmetric aes key is generated for high-throughput bulk data encryption
                #while rsa is utilized to securely distribute this ephemeral symmetric key
                print("Encrypting file...")
                #generate a cryptographically secure random 16-byte symmetric aes key
                aes_key = get_random_bytes(16)

                #encrypt the payload using aes in galois/counter mode
                #this provides both strict confidentiality and authenticated encryption
                with open(filepath, 'rb') as f_in:
                    file_data = f_in.read()
                
                cipher_aes = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
                encrypted_file_content = cipher_aes.nonce + tag + ciphertext

                #construct a cryptographic key ring loop iteratively encrypting the
                #aes key for every authorized recipient public key using rsa-oaep
                key_ring = {}
                for key_username, pub_key_pem in public_keys.items():
                    public_key = RSA.import_key(pub_key_pem)
                    cipher_rsa = PKCS1_OAEP.new(public_key)
                    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                    key_ring[key_username] = base64.b64encode(encrypted_aes_key).decode('utf-8')

                #applies a digital signature over the encrypted payload using the
                #senders private key and the probabilistic signature scheme
                #providing rigorous non-repudiation for the clinical dataset
                signature_b64 = ""
                proceed_upload = True
                if role == 'Researcher':
                    print("Signing encrypted file...")
                    sign_password = getpass.getpass("Password to unlock private key for signing: ")
                    private_key = load_private_key(username, sign_password)
                    if private_key:
                        h = SHA256.new(encrypted_file_content)
                        signer = pss.new(private_key)
                        signature = signer.sign(h)
                        signature_b64 = base64.b64encode(signature).decode('utf-8')
                        print("File signed successfully.")
                    else:
                        print("Failed to load private key. Upload cancelled.")
                        proceed_upload = False

                if proceed_upload:
                    #package the ciphertext and associated cryptographic metadata for transit
                    upload_files = {'file': (os.path.basename(filepath), encrypted_file_content, 'application/octet-stream')}
                    upload_data = {
                        'username': username,
                        'role': role,
                        'allowed_roles': role,
                        'key_ring_loop': json.dumps(key_ring),
                        'signature': signature_b64
                    }

                    print(f"Uploading encrypted file {os.path.basename(filepath)}...")
                    upload_response = requests.post(f"{SERVER_URL}/upload", files=upload_files, data=upload_data)
                    print(f"Server response: {upload_response.json()['message']}")
            else:
                print("No file selected.")
        else:
            if role in ['Clinician', 'Researcher']:
                download_choice = input_with_timeout("Do you want to download a file? (y/N):")
            else:
                download_choice = input_with_timeout("Do you want to verify the signature of a role? (y/N):")
            if download_choice is None:
                return # Timeout occurred, end session

            if download_choice.lower() == 'y':
                list_and_download_files(username, role)
        return # End of successful session

    # This part handles password failure or other errors from step 1
    login_attempts += 1
    print(f"\n--- Server Response ---\n{response.json().get('message', 'An unknown error occurred.')}\n-----------------------\n")

    if login_attempts >= 3:
        choice_reg = input("Login failed three times. Would you like to create an account? (Y/n) ")
        if choice_reg.upper() == 'Y':
            while True:
                reg_username = input("Enter new username: ")
                if not (MIN_USERNAME_LENGTH <= len(reg_username) <= MAX_USERNAME_LENGTH):
                    print(f"Username must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters.")
                elif not USERNAME_REGEX.match(reg_username):
                    print("Username can only contain letters, numbers, underscores, and dashes.")
                else:
                    break
            while True:
                reg_password = getpass.getpass("Enter new password: ")
                if (any(c.isupper() for c in reg_password) and any(c.islower() for c in reg_password) and any(c.isdigit() for c in reg_password) and any(not c.isalnum() for c in reg_password)):
                    break
                else:
                    print("\nPassword is not strong enough. It must contain at least one of each of the following:\n- An uppercase letter (A-Z)\n- A lowercase letter (a-z)\n- A number (0-9)\n- A special character (e.g., !, @, #, $)\n")
            while True:
                reg_role = input("Enter role (Clinician, Researcher, Auditor): ").capitalize()
                if reg_role in ['Clinician', 'Researcher', 'Auditor']: break
                print("Invalid role. Please choose from Clinician, Researcher, or Auditor.")
            
            print("\nGenerating key pair for your account...")
            public_key_pem = generate_and_save_keys(reg_username, reg_password)
            reg_response = requests.post(f"{SERVER_URL}/register", json={'username': reg_username, 'password': reg_password, 'role': reg_role, 'public_key': public_key_pem})

            if reg_response.status_code == 201:
                print(f"\n--- Server Response ---\n{reg_response.json()['message']}\n-----------------------\n")
                provisioning_uri = reg_response.json().get('provisioning_uri')
                print("ACTION REQUIRED: To enable Multi-Factor Authentication, please scan the following QR code with your authenticator app (e.g., Google Authenticator).")
                qr = qrcode.QRCode()
                qr.add_data(provisioning_uri)
                qr.print_tty()
                secret_key = provisioning_uri.split('secret=')[1].split('&')[0]
                print(f"\nIf you cannot scan the QR code, manually enter this secret key into your app: {secret_key}")
                print("\nRegistration complete. Please restart the client to log in.")
            else:
                print(f"\n--- Server Response ---\n{reg_response.json().get('message', 'Registration failed.')}\n-----------------------\n")
    else:
        main() # Retry login

if __name__ == '__main__':
    main()