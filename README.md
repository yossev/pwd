                        
# Introducing PWD

PWD is a [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy) based password management CLI application, made with simplicity in mind. Inspired by [pass](https://www.passwordstore.org/) - the standard unix password manager

## Features

- **AES Encryption**: PWD uses AES encryption to secure your passwords. Each password is encrypted with a unique master key, ensuring that your sensitive data remains protected.

- **Cross-Platform**: PWD is designed to work seamlessly on Linux, macOS, and Windows, making it a versatile tool for users on different operating systems.

- **Password Management**: Add, delete, and retrieve passwords with ease. PWD helps you manage your credentials efficiently through a command-line interface.

- **Password Generation**: Generate strong, random passwords with customizable options for length, uppercase letters, digits, and symbols.

- **Key Management**: Generate and store encryption keys securely. The master key is essential for encrypting and decrypting your passwords.

- **Clipboard Integration**: Quickly copy your generated or retrieved passwords to the clipboard for convenience.

- **Service Listing**: List all stored services to easily review your password management.

## Setup
1. **Clone the Repository**:
    ```git clone https://github.com/yossev/pwd.git```
    ```cd pwd```
    
    

2. **Install Dependencies**:
    Ensure you have Python 3 installed. Then, install the required packages:
    ```
    pip install -r requirements.txt
    ```

3. **Run the Application**:
    You can start using PWD directly from the command line :
    ```python pwd.py gen```
    
    
<hr >   
**Calling ```python pwd.py gen`` will generate a new `key` , this key is the master key that you will encrypt and decrypt
All your passwords with, once you have the key generated you can call `python pwd.py` to add a new password.**


## Usage

Very intuitive and interactive CLI, no need to learn anything scripting related.

- **Add a Password**:
    ``` python pwd.py add ```
    

- **Delete a Password**:
  ``` python pwd.py delete ```

- **Retrieve a Password**:
   ``` python pwd.py ret ```

- **Generate a New Encryption Key**:
   ``` python pwd.py gen-key ```

- **Generate a Password**:
    ``` python pwd.py gen ```  _Generated passwords need to be added/registered manually as of V1.0 ._

- **List All Services**:
   ``` python pwd.py list ```

- **Display Help**:
    ``` python pwd.py help ```

## Security

- Ensure that your master key is stored securely. Losing the key means losing access to your encrypted passwords.
- Use strong, unique passwords and consider generating new ones periodically.

## Todo
- [ ] Fix some input related bugs
- [ ] Add editing functionality
- [ ] Implement an API Endpoint for the program ( run it on a cloud platform )
- [ ] Find an alternative for the JSON Storage
- [ ] importation and exporation


## Contributing

Contributions are welcome! Please Check the [Github Repo](https://github.com/yossev/pwd) to get started.

## License

This project is licensed under the MIT License.

## Acknowledgements

- The [Cryptography](https://cryptography.io/en/latest/) library for AES encryption.
- The [pyperclip](https://pypi.org/project/pyperclip/) library for clipboard operations.
- PWD is made with <3 by [Yossef Hisham](https://yossev.github.io/NewPort/)
