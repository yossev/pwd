import argparse
import hashlib
from cryptography.fernet import Fernet # type: ignore
import json
import os
import pyperclip
import secrets
import time
import string
import logging
import requests


# LOGGER
logging.basicConfig(
    filename='transactions.log',
    level=logging.INFO,  
    format='%(asctime)s - %(levelname)s - %(message)s',
)

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
    logging.info(f"Added password for service: {service}")


def delete_password(service, key):
    cipher_suite = get_cipher_suite(key)
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            passwords = json.load(f)
        if service in passwords:
            with open(STORAGE_FILE, 'w') as f:
                json.dump(passwords, f, indent=4)
            try:
                encrypted_password = passwords[service]['password']
                cipher_suite.decrypt(encrypted_password.encode())
                del passwords[service]
                with open(STORAGE_FILE, 'w') as f:
                    json.dump(passwords, f, indent=4)
                print(f"Password for {service} has been deleted.")
                logging.info(f"Password for {service} has been deleted.")
            except Exception as e:
                print("Error with the encryption key. Unable to delete the password , please make sure the key is correct.")
                logging.warning(f"Failed to delete password for service: {service}. Key might be invalid.")
        else:
            print(f"No password found for service: {service}.")
            logging.warning(f"Attempted to delete non-existent password for service: {service}")
    else:
        print("No Passwords stored yet")


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
                print(f"Password : {decrypted_password}")
                copy_pass = input("Would you like to copy your password ? (Y/N):  \n")
                if copy_pass.lower() ==  'y':
                    pyperclip.copy(decrypted_password)
                    print("Password Copied Successfully")
                elif copy_pass.lower() == 'n':
                    exit
                else:
                    print("Not a valid reponse.")
                    exit
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
    logging.info("New Key has been generated")
    print("\nPlease store this key somewhere safe. You will need it to access your passwords.")
    
    save_choice = input("Would you like to save the key to a file? (Y/N): \n")
    if save_choice.lower() == 'y':
        key_file_path = input("Enter the file path where you want to save the key: \n")
        if key_file_path == "":
            print("please enter a valid file path")
            exit
        with open(key_file_path, 'wb') as key_file:
            key_file.write(key)
        print(f"Key saved to {key_file_path}")
    else:
        copy_choice = input("Would you like to copy your KEY to the Clipboard? (Y/N): \n")
        if copy_choice.lower() == 'y':
            pyperclip.copy(key.decode())
            print("Your Key has been copied. please keep it safe.")
        elif copy_choice.lower() == 'n':
            exit
        else:
            print("Not a valid reponse.")


def generate_password(length=12, include_uppercase=True, include_digits=True, include_symbols=False):
    include_symbols_choice = input("Woudld you like to include Symbols in your generated password? (Y/N) \n")
    if include_symbols_choice.lower() == 'y':
        include_symbols = True

    character_pool = string.ascii_lowercase
    
    if include_uppercase:
        character_pool += string.ascii_uppercase
    if include_digits:
        character_pool += string.digits
    if include_symbols:
        character_pool += string.punctuation

    print("Generating password...")
    time.sleep(2)
    password = ''.join(secrets.choice(character_pool) for i in range(length))
    generated_password_choice = input("Password has been generated.\nC -> copy , S -> show\n")
    if generated_password_choice.lower() == 'c':
        pyperclip.copy(password)
        print("Password has been copied Successfully.")
    elif generated_password_choice.lower() == 's':
        print(f"Here is your generated password {password}")
    else:
        print("Not a valid response.")
        exit

def list_services():
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE, 'r') as f:
            passwords = json.load(f)

        if passwords:
            print("Here are all the services stored currently :\n")
            for service in passwords:
                print(f"{service}")
        else:
            print("No services stored yet.")
    else:
        print("No password file found.")


# PASSWORD BREACH CHECKER FUNCTION

def check_password_breach(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
    return 0




def main():
    parser = argparse.ArgumentParser(
    description="",
    epilog="use python pwd.py help to get started with PWD."
)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    subparsers = parser.add_subparsers(dest="command", help="commands")

    print(ASCII_ART)
    print("Welcome to PWD. the Unix Philosophy inspired Password manager.")


    # Help Command
    help_parser = subparsers.add_parser('help', help='Display all commands')
    # Add Command
    add_parser = subparsers.add_parser('add', help='Add a new password')
    add_parser.add_argument('service', nargs='?', help='The service name')
    add_parser.add_argument('username', nargs='?', help='The username')
    add_parser.add_argument('password', nargs='?', help='The password')

    # Delete Command
    delete_parser = subparsers.add_parser('delete', help="Delete a password.")
    delete_parser.add_argument('service', nargs='?', help="The service to be deleted.")

    # Retrieve Argument
    retrieve_parser = subparsers.add_parser('ret', help="Retrieve a password.")
    retrieve_parser.add_argument('service', nargs='?', help="Service to retrieve the password from.")

    # Generate Password Argument
    gen_parser = subparsers.add_parser('gen', help="Generate a new password.")

    # gen-key parser
    key_parser = subparsers.add_parser('gen-key', help="Generate a new encryption key.")

    # List Parser
    list_parser = subparsers.add_parser('list', help="List all the services that have passwords.")

    # Breach Checker
    breach_parser = subparsers.add_parser('check', help="Check for password leaks/breachers")
    breach_parser.add_argument('password', nargs='?', help="The password to check")


    args = parser.parse_args()

    if args.command == 'add':
        service = args.service or input("Enter the service name: ")
        username = args.username or input("Enter the username: ")
        password = args.password or input("Enter the password: ")
        key = input("Enter your encryption key: ")
        add_password(service, username, password, key)
        print("Adding password")
        time.sleep(2)
        print(f"Password for {service} added successfully!")
        
    elif args.command == 'delete':
        service = args.service or input("Enter the Service to be deleted :\n")
        key = input("Enter your encryption key: ").encode()
        confirmation = input(" Are you sure you want to delete this password entry? ( Y / N )")
        if confirmation.lower() == 'y':
            print("Deleting entry...")
            time.sleep(2)
            delete_password(service, key)
            print(f"Entry for {service} has been deleted successfully.")
        elif confirmation.lower() == 'n':
            print("Deletion Canceled.")

    elif args.command == 'ret':
        service = args.service or input("Please Enter the Service you wanna retrieve: ")
        key = input("Enter your encryption key: ")
        key = key.encode()
        print("Getting your Password...")
        time.sleep(2)
        retrieve_password(service, key)

    elif args.command == 'check':
        password = args.password or input("Enter the password to check : \n")
        print("Checking password...")
        time.sleep(1)
        breach_count = check_password_breach(password)
        if breach_count:
            print(f"Warning: This password has been found in {breach_count} data breaches!")
            print("It's strongly recommended to change this password.")
        else:
            print("Good news! This password hasn't been found in any known data breaches.")
        logging.info(f"Password breach check performed. Result: {'Compromised' if breach_count else 'Not compromised'}")
    
    elif args.command == 'gen-key':
        generate_key()
    
    elif args.command == 'gen':
        generate_password()
    
    elif args.command == 'list':
        list_services()

    elif args.command == 'help' or args.command == 'h':
        parser.print_help()

if __name__ == '__main__':
    main()