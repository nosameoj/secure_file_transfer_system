# /home/nosameoj/Crypto/secure_file_transfer_system/client.py

"""
This script acts as the client application.
Users will run this from their terminal to interact with the server.
"""

import requests
import getpass
import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from Crypto.PublicKey import DSA

SERVER_URL = 'http://127.0.0.1:5000'
login_attempts = 0


def generate_and_save_keys(username, password):
    """
    Generates a new DSA key pair and saves them to disk locally.
    The private key is encrypted with the user's password.

    Args:
        username (str): The username, used for creating a key directory.
        password (str): The password used to encrypt the private key.

    Returns:
        str: The public key in PEM format as a string.
    """
    # Generate a 2048-bit DSA key
    key = DSA.generate(2048)
    public_key = key.publickey()

    keys_dir = os.path.join('client_keys', username)
    os.makedirs(keys_dir, exist_ok=True)

    # Export and save the encrypted private key
    with open(os.path.join(keys_dir, f"{username}_private_key.pem"), 'wb') as f:
        f.write(key.export_key(format='PEM', passphrase=password, pkcs8=True, protection='scryptAndAES128-CBC'))

    # Export and save the public key
    pem_public = public_key.export_key(format='PEM')
    with open(os.path.join(keys_dir, f'{username}_public_key.pem'), 'wb') as f:
        f.write(pem_public)

    print(f"Key pair generated and saved in '{keys_dir}'")
    return pem_public.decode('utf-8')

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
                choice = int(input(f"Enter the number of the file to download (1-{len(files)}), or 0 to cancel: "))
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

        print(f"\nDownloading '{original_filename}'...")
        download_response = requests.post(f"{SERVER_URL}/download/{unique_filename}", json={'username': username, 'role': role})

        if download_response.status_code == 200:
            save_dir = 'downloads'
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, original_filename)
            with open(save_path, 'wb') as f:
                f.write(download_response.content)
            print(f"File saved successfully to '{save_path}'")
        else:
            print(f"Failed to download file: {download_response.json().get('message')}")

    except requests.exceptions.RequestException as e:
        print(f"A network error occurred: {e}")

def main():
    global login_attempts
    """Main function to run the client application."""
    print("--- Secure Clinical Data Sharing System ---")


    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    # Attempt to log in
    response = requests.post(f"{SERVER_URL}/login", json={'username': username, 'password': password})

    # print("\n--- Server Response ---")
    # print(f"Status Code: {response.status_code}")
    # print(response.json())
    # print("-----------------------\n")

    if response.status_code == 401:
        login_attempts += 1
        if login_attempts >= 3: 
    
            choice_reg = input("Login failed thrice, would you like to create an account? (Y/n)")
            if choice_reg.upper() == 'Y':
                username = input("Enter username:")
                # Password validation loop
                while True:
                    password = getpass.getpass("Enter new password: ")
                    if (any(c.isupper() for c in password) and
                        any(c.islower() for c in password) and
                        any(c.isdigit() for c in password) and
                        any(not c.isalnum() for c in password)):
                        break
                    else:
                        print("\nPassword is not strong enough. It must contain at least one of each of the following:")
                        print("- An uppercase letter (A-Z)")
                        print("- A lowercase letter (a-z)")
                        print("- A number (0-9)")
                        print("- A special character (e.g., !, @, #, $)\n")
                # Role validation loop
                while True:
                    role = input("Enter role (Clinician, Researcher, Auditor): ").capitalize()
                    if role in ['Clinician', 'Researcher', 'Auditor']:
                        break
                    print("Invalid role. Please choose from Clinician, Researcher, or Auditor.")
                print("\nGenerating key pair for your account...")
                public_key_pem = generate_and_save_keys(username, password)

                response = requests.post(f"{SERVER_URL}/register", json={
                    'username': username,
                    'password': password,
                    'role': role,
                    'public_key': public_key_pem
                })
                print(f"\n--- Server Response ---\n{response.json()['message']}\n-----------------------\n")
                main()
        else:
            main()
    elif response.status_code == 200:
        print(response.json()['message'])   
        role = response.json()['role']
        print("Your role is:", role)

        choice = input("Do you want to upload a file? (y/N): ")
        if choice.lower() == 'y':
            # Hide the root Tkinter window
            root = Tk()
            root.withdraw()
            print("Opening file browser to select a file...")
            filepath = askopenfilename()
            root.destroy()

            if filepath: # Proceed if a file was selected
                with open(filepath, 'rb') as f:
                    files = {'file': (os.path.basename(filepath), f)}
                    user_data = {'username': username, 'role': role}
                    print(f"Uploading {filepath}...")
                    upload_response = requests.post(f"{SERVER_URL}/upload", files=files, data=user_data)
                    print(f"Server response: {upload_response.json()['message']}")
            else:
                print("No file selected.")
        else:
            download_choice = input("Do you want to download a file? (y/N): ")
            if download_choice.lower() == 'y':
                list_and_download_files(username, role)

if __name__ == '__main__':
    main()