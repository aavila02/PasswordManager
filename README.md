# Password Manager

A secure and simple password manager built using Python that stores encrypted passwords for different accounts. The password manager allows users to:
- Add new passwords for different services (e.g., Instagram, Gmail).
- Retrieve saved passwords.
- Generate strong passwords.
- Securely encrypt and store passwords using AES-GCM encryption.

## Features
- **Encryption**: Uses `AES-GCM` encryption to securely store passwords.
- **Master Password**: Protects all stored passwords by requiring a master password to access or add new passwords.
- **Persistent Storage**: Passwords and the encryption salt are stored in files (`passwords.json` and `salt.bin`) for persistent use across multiple sessions.
- **Strong Password Generator**: Generates strong random passwords with customizable length.
  
## How it Works
1. The user sets a **master password** when running the password manager.
2. The **master password** is used to generate an encryption key, which encrypts and decrypts passwords stored in the manager.
3. Passwords are stored in a file (`passwords.json`), and the encryption key is derived using a **salt** stored in `salt.bin`.
4. The **AES-GCM** encryption ensures that the passwords are securely stored and can only be accessed using the correct master password.

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

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

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
   - **Add new password**: Add and save a new password for a service.
   - **Retrieve a password**: Decrypt and view a saved password.
   - **Generate strong password**: Generate a secure random password.
   - **Exit**: Exit the password manager.

3. The passwords are securely stored and encrypted. You need to enter the same master password in future sessions to access or add new passwords.

## Security Features
- **AES-GCM encryption**: Ensures that passwords are stored securely and cannot be accessed without the master password.
- **Master password protection**: The master password is required to unlock all stored passwords.
