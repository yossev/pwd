import argparse
from cryptography.fernet import Fernet
import json
import os


STORAGE_FILE = 'passwords.json'
ASCII_ART = """
 /$$$$$$$  /$$      /$$ /$$$$$$$ 
| $$__  $$| $$  /$ | $$| $$__  $$
| $$  \ $$| $$ /$$$| $$| $$  \ $$
| $$$$$$$/| $$/$$ $$ $$| $$  | $$
| $$____/ | $$$$_  $$$$| $$  | $$
| $$      | $$$/ \  $$$| $$  | $$
| $$      | $$/   \  $$| $$$$$$$/
|__/      |__/     \__/|_______/ 
                                 """

def get_cipher_suite(key):
    return Fernet(key)


def add_password(service, username, password, key):
    cipher_suite = get_cipher_suite(key)
    encrypted_password = cipher_suite.encrypt(password.encode())


    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            passwords =  json.load(f)
    else:
        passwords = {}


    passwords[service] = {
       'username': username,
       'password': encrypted_password.decode()
    }

    with open(STORAGE_FILE, 'w') as f:
        json.dump(passwords, f, indent=4)


def delete_password(service):
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            passwords = json.load(f)
        
        if service in passwords:
            del passwords[service]
            with open(STORAGE_FILE, 'w') as f:
                json.dump(passwords, f, indent=4)
            print(f"Password for {service} has been deleted.")
        else:
            print(f"No password found for service: {service}.")
    else:
        ("No Passwords stored yet")


def retrieve_password(service, key):
    cipher_suite = get_cipher_suite(key)
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            passwords = json.load(f)
        
        if service in passwords:
            encrypted_password = passwords[service]['password']

            try:
                print("Decrypting Password...")
                decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                print(f"Username : {passwords[service]['username']}")
                print(f"Password : {passwords[service]['password']}")
            except Exception as e:
                print("Error decrypting the password. Invalid key or corrupted data.")
        else:
            print(f"No password found for service: {service}.")
    else:
        ("No Passwords stored yet")


def generate_key():
    key = Fernet.generate_key() # FERNET USES AES Keys
    print("Your encryption key has been generated:")
    print(key.decode())
    print("\nPlease store this key somewhere safe. You will need it to access your passwords.")
    
    save_choice = input("Would you like to save the key to a file? (Y/N): ")
    if save_choice.lower() == 'y':
        key_file_path = input("Enter the file path where you want to save the key: ")
        with open(key_file_path, 'wb') as key_file:
            key_file.write(key)
        print(f"Key saved to {key_file_path}")


def main():
    parser = argparse.ArgumentParser(
    description="Password Manager CLI",
    epilog="Use 'python pwd_manager.py add' to add a password and get started with PWD."
)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    subparsers = parser.add_subparsers(dest="command", help="commands")

    print(ASCII_ART)
    print("Welcome to the password manager CLI!")

    # Add Command
    add_parser = subparsers.add_parser('add', help='Add a new password')
    add_parser.add_argument('service', nargs='?', help='The service name')
    add_parser.add_argument('username', nargs='?', help='The username')
    add_parser.add_argument('password', nargs='?', help='The password')

    # Delete Command
    delete_parser = subparsers.add_parser('delete', help="Delete a password")
    delete_parser.add_argument('service', nargs='?', help="The service to be deleted")

    # Retrieve Argument
    retrieve_parser = subparsers.add_parser('ret', help="Retrieve a password")
    retrieve_parser.add_argument('service', nargs='?', help="Service to retrieve the password from")


    # init parser
    key_parser = subparsers.add_parser('init', help="Generate a new encryption key")

    args = parser.parse_args()

    if args.command == 'add':
        service = args.service or input("Enter the service name: ")
        username = args.username or input("Enter the username: ")
        password = args.password or input("Enter the password: ")
        key = input("Enter your encryption key: ")
        add_password(service, username, password, key)
        print(f"Password for {service} added successfully!")
        
    elif args.command == 'delete':
        service = args.service or input("Enter the Service to be deleted")
        confirmation = input(" Are you sure you want to delete this password entry? ( Y / N )")
        if confirmation.lower() == 'y':
            print("Deleting entry...")
            delete_password(service)
            print(f"Entry for {service} has been deleted successfully.")
        elif confirmation.lower() == 'n':
            print("Deletion Canceled.")

    elif args.command == 'ret':
        service = args.service or input("Please Enter the Service you wanna retrieve: ")
        key = input("Enter your encryption key: ")
        retrieve_password(service, key)

    elif args.command == 'init':
        generate_key()

    else:
        parser.print_help()

if __name__ == '__main__':
    main()