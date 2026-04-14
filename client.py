# /home/nosameoj/Crypto/secure_file_transfer_system/client.py

#this script runs the client side 

import requests
import getpass
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
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
    #gathers the user input, with a timeout to logout user after 60 seconds of inactivity
    #uses "select" for unix systems
    #uses msvcrt for windows

    print(prompt, end=' ', flush=True)
    if os.name == 'nt':
        import msvcrt
        import time
        start_time = time.time()
        input_string = ""
        while True:
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                if char in ('\x00', '\xe0'):
                    msvcrt.getwch() # Consume scan code for special keys like arrows
                    continue
                if char == '\x03': # Ctrl+C support
                    raise KeyboardInterrupt
                if char in ('\r', '\n'):
                    print()
                    return input_string.strip()
                elif char == '\x08': # Backspace support
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

    #generates an RSA key pair, and saves both to local disk, keys are encrpyted locally with users password
    #requires vars to username and password
    #returns the public key in a PEM format string, to be later saved in users.json

    # Generate a 2048-bit RSA key for encryption and signing
    key = RSA.generate(2048)
    public_key = key.publickey()

    keys_dir = 'client_keys'
    os.makedirs(keys_dir, exist_ok=True)

    # Export and save the encrypted private key
    with open(os.path.join(keys_dir, f"{username}_private_key.pem"), 'wb') as f:
        f.write(key.export_key(format='PEM', passphrase=password, pkcs=8, protection='scryptAndAES128-CBC'))

    # Export and save the public key
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
            # --- Decryption Process ---
            print("File downloaded. Enter your password to decrypt your private key for file decryption.")
            password = getpass.getpass("Password: ")
            private_key = load_private_key(username, password)
            if not private_key:
                return # Failed to load private key

            # 1. Find this user's encrypted AES key in the key ring
            key_ring = selected_file['key_ring_loop']
            encrypted_aes_key_b64 = key_ring.get(username)
            if not encrypted_aes_key_b64:
                print("Error: Could not find an encryption key for your user in the file's metadata.")
                return
            
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            
            # 2. Decrypt the AES key with the user's private key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # 3. Decrypt the file content with the AES key
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

    # print("\n--- Server Response ---")
    # print(f"Status Code: {response.status_code}")
    # print(response.json())
    # print("-----------------------\n")
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

        # Post-login actions
        choice = input_with_timeout("Do you want to upload a file? (y/N):")
        if choice is None:
            return # Timeout occurred, end session

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

                # --- Client-side Encryption ---
                print("Encrypting file...")
                # 1. Generate a random symmetric AES key
                aes_key = get_random_bytes(16)

                # 2. Encrypt the file with the AES key (AES/GCM mode)
                with open(filepath, 'rb') as f_in:
                    file_data = f_in.read()
                
                cipher_aes = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
                encrypted_file_content = cipher_aes.nonce + tag + ciphertext

                # 3. Create the key ring
                key_ring = {}
                for key_username, pub_key_pem in public_keys.items():
                    public_key = RSA.import_key(pub_key_pem)
                    cipher_rsa = PKCS1_OAEP.new(public_key)
                    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                    key_ring[key_username] = base64.b64encode(encrypted_aes_key).decode('utf-8')

                # 4. Prepare for upload
                upload_files = {'file': (os.path.basename(filepath), encrypted_file_content, 'application/octet-stream')}
                upload_data = {
                    'username': username,
                    'role': role,
                    'allowed_roles': role,
                    'key_ring_loop': json.dumps(key_ring)
                }

                print(f"Uploading encrypted file {os.path.basename(filepath)}...")
                upload_response = requests.post(f"{SERVER_URL}/upload", files=upload_files, data=upload_data)
                print(f"Server response: {upload_response.json()['message']}")
            else:
                print("No file selected.")
        else:
            download_choice = input_with_timeout("Do you want to download a file? (y/N):")
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