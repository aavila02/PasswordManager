# Password Manager

A secure, intuitive, and user-friendly password manager built using Python. The manager provides a Graphical User Interface (GUI) and uses strong encryption mechanisms to store and retrieve passwords safely.

## Features
- **Graphical User Interface**: A Tkinter-based GUI allows for intuitive management of passwords, eliminating the need for terminal-based commands.
- **Encryption**: Uses `AES-GCM` encryption to securely store passwords.
- **Master Password**: Protects all stored passwords by requiring a master password to access or add new passwords.
- **Persistent Storage**: Passwords and the encryption salt are stored in files (`passwords.json` and `salt.bin`) for persistent use across multiple sessions.
- **Strong Password Generator**: Generates strong random passwords with customizable length.
- **Delete Passwords**: Easily delete passwords for specific websites or applications.
- **View Saved Websites**: Displays a list of all saved websites/applications without revealing the passwords.
  
## How it Works
1. The user sets a **master password** when running the password manager.
2. The **master password** is used to generate an encryption key, which encrypts and decrypts passwords stored in the manager.
3. Passwords are stored in a file (`passwords.json`), and the encryption key is derived using a **salt** stored in `salt.bin`.
4. A **Tkinter GUI** simplifies interaction, providing options to add, retrieve, delete, view, or generate passwords.
5. The **AES-GCM** encryption ensures that the passwords are securely stored and can only be accessed using the correct master password.

## Setup and Installation

### Prerequisites
- Python 3.x
- `cryptography` library for encryption

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/password-manager.git
    cd password-manager
    ```

2. Install the required dependencies

3. Run the password manager:
    ```bash
    python password_manager.py
    ```

## File Structure
- **`password_manager.py`**: The main script for running the password manager.
- **`passwords.json`**: The file where encrypted passwords are stored.
- **`salt.bin`**: The file storing the salt used to derive the encryption key.

## Usage

1. Run the program and enter your master password.
2. Choose an option:
   - **Add New Password**: Add and save a new password for a service.
   - **Retrieve Password**: Decrypt and view a saved password for a specific website or application.
   - **Generate Strong Password**: Generate a secure random password of customizable length.
   - **View Saved Websites**: Display a list of saved websites/applications without revealing the actual passwords.
   - **Delete Password**: Remove a saved password from the manager.
   - **Exit**: Close the application.

3. All passwords are securely encrypted and stored. You must enter the same master password in future sessions to access your saved data.

## Security Features
- **AES-GCM encryption**: Ensures that passwords are stored securely and cannot be accessed without the master password.
- **Master password protection**: The master password is required to unlock all stored passwords.
- **Key derivation using Scrypt**: Adds an additional layer of security by deriving encryption keys from the master password.
- **Error Handling**: Alerts for invalid master passwords or decryption issues, ensuring secure and user-friendly interaction.
