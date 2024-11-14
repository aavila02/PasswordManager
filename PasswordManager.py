import os
import json
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
import secrets

# Key generation using a password and a constant salt
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt password using AES-GCM
def encrypt_password(key: bytes, password: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES GCM requires a nonce
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext)

# Decrypt password using AES-GCM
def decrypt_password(key: bytes, enc_password: bytes) -> str:
    enc_password = base64.urlsafe_b64decode(enc_password)
    nonce = enc_password[:12]
    ciphertext = enc_password[12:]
    aesgcm = AESGCM(key)
    password = aesgcm.decrypt(nonce, ciphertext, None)
    return password.decode()

# Generate a strong password
def generate_strong_password(length=16) -> str:
    return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()') for _ in range(length))

# Save encrypted password to a file
def save_passwords_to_file(filename: str, passwords: dict):
    with open(filename, 'w') as file:
        json.dump(passwords, file)

# Load encrypted passwords from a file
def load_passwords_from_file(filename: str) -> dict:
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return {}

# Load or generate a salt
def get_salt():
    salt_file = "salt.bin"
    if os.path.exists(salt_file):
        with open(salt_file, 'rb') as file:
            return file.read()
    else:
        salt = os.urandom(16)
        with open(salt_file, 'wb') as file:
            file.write(salt)
        return salt

# Hash the master password using SHA-256
def hash_master_password(master_password: str) -> bytes:
    return hashlib.sha256(master_password.encode()).digest()

# Verify master password by comparing with stored hash
def verify_master_password(master_password: str) -> bool:
    hashed_password = hash_master_password(master_password)
    if os.path.exists("master_hash.bin"):
        with open("master_hash.bin", "rb") as f:
            stored_hash = f.read()
        return hashed_password == stored_hash
    else:
        # If no hash exists, store the hash on first run
        with open("master_hash.bin", "wb") as f:
            f.write(hashed_password)
        return True

# Prompt for a secure master password with a minimum length requirement
def get_secure_master_password() -> str:
    while True:
        master_password = getpass.getpass('Enter your master password (min 8 characters): ')
        if len(master_password) >= 8:
            return master_password
        else:
            print("Password must be at least 8 characters long.")

# Main Password Manager
def password_manager():
    # Get or generate a constant salt
    salt = get_salt()

    # Prompt for and verify the master password
    master_password = get_secure_master_password()
    if not verify_master_password(master_password):
        print("Incorrect master password. Access denied.")
        return  # Exit if the master password doesn't match the stored hash

    # Generate the encryption key from the master password and salt
    key = generate_key(master_password, salt)
    
    filename = "passwords.json"
    passwords = load_passwords_from_file(filename)
    
    while True:
        print("\n1. Add new password")
        print("2. Retrieve a password")
        print("3. Generate strong password")
        print("4. Exit")

        choice = input("\nChoose an option: ")

        if choice == '1':
            site = input("Enter the website/application name: ")
            password = getpass.getpass(f"Enter the password for {site}: ")
            enc_password = encrypt_password(key, password)
            passwords[site] = enc_password.decode()
            save_passwords_to_file(filename, passwords)
            print(f"Password for {site} saved successfully.")

        elif choice == '2':
            site = input("Enter the website/application name: ")
            if site in passwords:
                enc_password = passwords[site]
                try:
                    password = decrypt_password(key, enc_password)
                    print(f"Password for {site}: {password}")
                except Exception as e:
                    print("Error decrypting password. Invalid master password or data.")
            else:
                print(f"No password found for {site}.")

        elif choice == '3':
            length = int(input("Enter desired password length: "))
            strong_password = generate_strong_password(length)
            print(f"Generated password: {strong_password}")

        elif choice == '4':
            print("Exiting Password Manager. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    password_manager()
