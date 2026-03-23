# /home/nosameoj/Crypto/secure_file_transfer_system/client.py

"""
This script acts as the client application.
Users will run this from their terminal to interact with the server.
"""

import requests
import getpass

SERVER_URL = 'http://127.0.0.1:5000'
login_attempts = 0


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
                response = requests.post(f"{SERVER_URL}/register", json={'username': username, 'password': password, 'role': role})
                main()
        else:
            main()
    elif response.status_code == 200:
        print(response.json()['message'])   
        print("Your role is:", response.json()['role'])     
    


if __name__ == '__main__':
    main()