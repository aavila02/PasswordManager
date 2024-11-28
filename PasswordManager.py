import os
import json
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

# --- Core Functions ---
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


def encrypt_password(key: bytes, password: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext)


def decrypt_password(key: bytes, enc_password: bytes) -> str:
    enc_password = base64.urlsafe_b64decode(enc_password)
    nonce = enc_password[:12]
    ciphertext = enc_password[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def generate_strong_password(length=16) -> str:
    return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()') for _ in range(length))


def save_passwords_to_file(filename: str, passwords: dict):
    with open(filename, 'w') as file:
        json.dump(passwords, file)


def load_passwords_from_file(filename: str) -> dict:
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return {}


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


def hash_master_password(master_password: str) -> bytes:
    return hashlib.sha256(master_password.encode()).digest()


def verify_master_password(master_password: str) -> bool:
    hashed_password = hash_master_password(master_password)
    if os.path.exists("master_hash.bin"):
        with open("master_hash.bin", "rb") as f:
            stored_hash = f.read()
        return hashed_password == stored_hash
    else:
        with open("master_hash.bin", "wb") as f:
            f.write(hashed_password)
        return True


# --- GUI Functions ---
def add_password():
    site = simpledialog.askstring("Add Password", "Enter website/application name:")
    if not site:
        return
    password = simpledialog.askstring("Add Password", f"Enter password for {site}:", show="*")
    if not password:
        return
    enc_password = encrypt_password(key, password)
    passwords[site] = enc_password.decode()
    save_passwords_to_file("passwords.json", passwords)
    messagebox.showinfo("Success", f"Password for {site} saved!")


def retrieve_password():
    site = simpledialog.askstring("Retrieve Password", "Enter website/application name:")
    if not site:
        return
    if site in passwords:
        try:
            enc_password = passwords[site]
            decrypted_password = decrypt_password(key, enc_password)
            messagebox.showinfo("Password", f"Password for {site}: {decrypted_password}")
        except Exception:
            messagebox.showerror("Error", "Failed to decrypt password. Invalid data or key.")
    else:
        messagebox.showerror("Error", f"No password found for {site}.")


def generate_password():
    length = simpledialog.askinteger("Generate Password", "Enter desired password length (8-32):", minvalue=8, maxvalue=32)
    if length:
        strong_password = generate_strong_password(length)
        messagebox.showinfo("Generated Password", f"Generated Password: {strong_password}")


def view_saved_websites():
    if passwords:
        sites = "\n".join(passwords.keys())  # Get all saved website/application names
        messagebox.showinfo("Saved Websites", f"Saved Websites:\n{sites}")
    else:
        messagebox.showinfo("Saved Websites", "No websites/applications saved yet.")


def delete_password():
    site = simpledialog.askstring("Delete Password", "Enter website/application name to delete:")
    if not site:
        return
    if site in passwords:
        del passwords[site]
        save_passwords_to_file("passwords.json", passwords)
        messagebox.showinfo("Success", f"Password for {site} deleted.")
    else:
        messagebox.showerror("Error", f"No password found for {site}.")


# --- Main App ---
salt = get_salt()
passwords = load_passwords_from_file("passwords.json")

master_password = simpledialog.askstring("Master Password", "Enter your master password (min 8 characters):", show="*")
if not master_password or len(master_password) < 8 or not verify_master_password(master_password):
    messagebox.showerror("Access Denied", "Invalid master password.")
    exit()

key = generate_key(master_password, salt)

# Create the main window
root = tk.Tk()
root.title("Password Manager")
root.geometry("400x400")

# Add a title label
title_label = tk.Label(root, text="Password Manager", font=("Helvetica", 16))
title_label.pack(pady=10)

# Add buttons for actions
add_button = ttk.Button(root, text="Add New Password", command=add_password)
add_button.pack(pady=5)

retrieve_button = ttk.Button(root, text="Retrieve Password", command=retrieve_password)
retrieve_button.pack(pady=5)

generate_button = ttk.Button(root, text="Generate Strong Password", command=generate_password)
generate_button.pack(pady=5)

view_button = ttk.Button(root, text="View Saved Websites", command=view_saved_websites)
view_button.pack(pady=5)

delete_button = ttk.Button(root, text="Delete Password", command=delete_password)
delete_button.pack(pady=5)

exit_button = ttk.Button(root, text="Exit", command=root.quit)
exit_button.pack(pady=20)

# Run the main loop
root.mainloop()
