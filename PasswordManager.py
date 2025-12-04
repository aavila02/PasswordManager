import os
import json
import base64
import hashlib
import time
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import pyperclip

class ModernPasswordManager:
    def __init__(self):
        self.key = None
        self.passwords = {}
        self.salt = None
        self.session_timeout = 300  # 5 minutes in seconds
        self.failed_attempts = 0
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes lockout
        self.last_lockout_time = 0
        self.last_activity = time.time()
        # IDs returned by Tkinter's after() for safe, main-thread timers
        self.session_timer = None
        self.is_locked = False
        self.root = None
        self.search_var = None
        self.listbox = None
        self.status_label = None
        self.timer_label = None
        self.clipboard_timer = None
        
    def clear_sensitive_data(self):
        """Securely clear sensitive data from memory"""
        if self.key:
            self.key = os.urandom(len(self.key))
            self.key = None
        self.passwords.clear()

    # --- Secure storage helpers ---
    def get_data_dir(self) -> str:
        """
        Return the directory used to store vault data.

        For simplicity, this is the same folder as the main script so that
        all vault files live alongside PasswordManager.py.
        """
        # Directory where this file lives
        data_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            os.makedirs(data_dir, mode=0o700, exist_ok=True)
            # Best-effort to tighten permissions; ignore on platforms that don't support it
            try:
                os.chmod(data_dir, 0o700)
            except Exception:
                pass
        except Exception:
            # Fallback to current directory if creation fails
            data_dir = "."
        return data_dir

    def _secure_write_bytes(self, path: str, data: bytes) -> None:
        """Write bytes to a file and try to enforce 0600 permissions."""
        with open(path, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    def _secure_write_text(self, path: str, data: str) -> None:
        """Write text to a file and try to enforce 0600 permissions."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        
    def is_account_locked(self):
        """Check if account is currently locked out"""
        if self.failed_attempts >= self.max_failed_attempts:
            time_since_lockout = time.time() - self.last_lockout_time
            if time_since_lockout < self.lockout_duration:
                return True
            else:
                self.failed_attempts = 0
                return False
        return False
    
    def validate_master_password_strength(self, password):
        """Validate master password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password meets security requirements"
    
    def check_password_strength(self, password):
        """Check password strength and return score/feedback"""
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")
            
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("Consider 12+ characters")
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
            
        strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        strength = strength_levels[min(score, 5)]
        
        return score, strength, feedback
    
    def update_activity(self):
        """Update last activity timestamp and reset session timer"""
        self.last_activity = time.time()
        # Only schedule UI timers once the root window exists
        if self.root:
            # Cancel any existing scheduled lock
            if self.session_timer is not None:
                try:
                    self.root.after_cancel(self.session_timer)
                except Exception:
                    pass
            # Schedule lock on inactivity using Tkinter's main thread
            self.session_timer = self.root.after(
                int(self.session_timeout * 1000), self.lock_session
            )
            self.update_timer_display()
    
    def update_timer_display(self):
        """Update the session timer display"""
        if self.timer_label and not self.is_locked:
            remaining = self.session_timeout - (time.time() - self.last_activity)
            if remaining > 0:
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                self.timer_label.config(text=f"Session expires in: {minutes:02d}:{seconds:02d}")
                self.root.after(1000, self.update_timer_display)
            else:
                self.timer_label.config(text="Session expired")
    
    def lock_session(self):
        """Lock the session due to inactivity"""
        self.is_locked = True
        self.clear_sensitive_data()
        messagebox.showwarning("Session Locked", "Session locked due to inactivity. Please re-authenticate.")
        self.show_unlock_dialog()
    
    def show_unlock_dialog(self):
        """Show dialog to unlock the session"""
        if self.root:
            self.root.withdraw()
        
        master_password = simpledialog.askstring(
            "Unlock Session", 
            "Session locked. Enter master password to unlock:", 
            show="*"
        )
        
        if master_password and self.verify_master_password(master_password):
            self.key = self.generate_key(master_password, self.salt)
            self.passwords = self.load_passwords_from_file("passwords.json")
            self.is_locked = False
            self.failed_attempts = 0
            self.update_activity()
            self.refresh_password_list()
            if self.root:
                self.root.deiconify()
            messagebox.showinfo("Success", "Session unlocked successfully!")
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= self.max_failed_attempts:
                self.last_lockout_time = time.time()
                messagebox.showerror("Account Locked", 
                    f"Too many failed attempts. Account locked for {self.lockout_duration // 60} minutes.")
                if self.root:
                    self.root.quit()
            else:
                remaining = self.max_failed_attempts - self.failed_attempts
                messagebox.showerror("Access Denied", 
                    f"Invalid password. {remaining} attempts remaining.")
                self.show_unlock_dialog()
    
    def copy_to_clipboard(self, text, auto_clear=True):
        """Copy text to clipboard with optional auto-clear"""
        try:
            pyperclip.copy(text)
            self.update_status("Copied to clipboard!")
            
            if auto_clear:
                # Clear clipboard after 30 seconds, scheduled on the Tkinter main thread
                if self.root:
                    if self.clipboard_timer is not None:
                        try:
                            self.root.after_cancel(self.clipboard_timer)
                        except Exception:
                            pass
                    self.clipboard_timer = self.root.after(30_000, self.clear_clipboard)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def clear_clipboard(self):
        """Clear clipboard for security"""
        try:
            pyperclip.copy("")
            self.update_status("Clipboard cleared for security")
        except:
            pass
    
    def update_status(self, message):
        """Update status message"""
        if self.status_label:
            self.status_label.config(text=message)
            # Clear status after 3 seconds
            self.root.after(3000, lambda: self.status_label.config(text="Ready"))

    def generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password and salt"""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_password(self, key: bytes, password: str) -> bytes:
        """Encrypt a password using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
        return base64.urlsafe_b64encode(nonce + ciphertext)

    def decrypt_password(self, key: bytes, enc_password: bytes) -> str:
        """Decrypt a password using AES-GCM"""
        enc_password = base64.urlsafe_b64decode(enc_password)
        nonce = enc_password[:12]
        ciphertext = enc_password[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    def generate_strong_password(self, length=16) -> str:
        """Generate a cryptographically strong password"""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(),.?":{}|<>'
        return ''.join(secrets.choice(chars) for _ in range(length))

    def save_passwords_to_file(self, filename: str, passwords: dict):
        """Save encrypted passwords to file"""
        try:
            data_dir = self.get_data_dir()
            target = os.path.join(data_dir, filename)
            # Add metadata
            data = {
                "version": "2.0",
                "created": time.time(),
                "passwords": passwords
            }
            self._secure_write_text(target, json.dumps(data, indent=2))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")

    def load_passwords_from_file(self, filename: str) -> dict:
        """Load encrypted passwords from file"""
        data_dir = self.get_data_dir()
        target = os.path.join(data_dir, filename)

        # Backwards compatibility: migrate legacy file from CWD if present
        legacy = filename
        if not os.path.exists(target) and os.path.exists(legacy):
            try:
                with open(legacy, "r", encoding="utf-8") as file:
                    raw = file.read()
                os.remove(legacy)
                self._secure_write_text(target, raw)
            except Exception:
                # If migration fails, fall back to reading legacy file directly
                target = legacy

        if os.path.exists(target):
            try:
                with open(target, 'r', encoding="utf-8") as file:
                    data = json.load(file)
                # Handle both old and new format
                if isinstance(data, dict) and "passwords" in data:
                    return data["passwords"]
                else:
                    return data  # Old format
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
                return {}
        return {}

    def get_salt(self):
        """Get or generate salt for key derivation"""
        data_dir = self.get_data_dir()
        salt_file = os.path.join(data_dir, "salt.bin")

        # Migrate legacy salt if present
        legacy = "salt.bin"
        if not os.path.exists(salt_file) and os.path.exists(legacy):
            try:
                with open(legacy, "rb") as f:
                    legacy_salt = f.read()
                os.remove(legacy)
                self._secure_write_bytes(salt_file, legacy_salt)
                return legacy_salt
            except Exception:
                pass

        if os.path.exists(salt_file):
            try:
                with open(salt_file, 'rb') as file:
                    return file.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read salt: {str(e)}")
                return None

        # Generate new salt
        salt = os.urandom(16)
        try:
            self._secure_write_bytes(salt_file, salt)
            return salt
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create salt: {str(e)}")
            return None

    def hash_master_password(self, master_password: str) -> bytes:
        """Hash master password using SHA-256"""
        return hashlib.sha256(master_password.encode()).digest()

    def _create_scrypt_master_record(self, master_password: str) -> dict:
        """
        Create a salted Scrypt-based record for the master password.

        The record is JSON-serializable and includes parameters so we can
        change work factors in the future without breaking verification.
        """
        salt = os.urandom(16)
        params = {
            "version": 2,
            "kdf": "scrypt",
            "n": 2**14,
            "r": 8,
            "p": 1,
        }
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=params["n"],
            r=params["r"],
            p=params["p"],
            backend=default_backend(),
        )
        derived = kdf.derive(master_password.encode())
        params["salt"] = base64.b64encode(salt).decode()
        params["hash"] = base64.b64encode(derived).decode()
        return params

    def _verify_scrypt_master_record(self, master_password: str, record: dict) -> bool:
        """Verify a master password against a Scrypt-based record."""
        try:
            if record.get("kdf") != "scrypt":
                return False
            n = record.get("n", 2**14)
            r = record.get("r", 8)
            p = record.get("p", 1)
            salt = base64.b64decode(record["salt"])
            stored_hash = base64.b64decode(record["hash"])
            kdf = Scrypt(
                salt=salt,
                length=len(stored_hash),
                n=n,
                r=r,
                p=p,
                backend=default_backend(),
            )
            kdf.verify(master_password.encode(), stored_hash)
            return True
        except Exception:
            return False

    def verify_master_password(self, master_password: str) -> bool:
        """Verify master password against stored hash"""
        data_dir = self.get_data_dir()
        hash_file = os.path.join(data_dir, "master_hash.bin")
        
        if os.path.exists(hash_file):
            try:
                with open(hash_file, "rb") as f:
                    raw = f.read()

                # Prefer the newer, JSON-based Scrypt record format
                try:
                    record = json.loads(raw.decode())
                    if self._verify_scrypt_master_record(master_password, record):
                        return True
                    return False
                except Exception:
                    # Legacy format: raw SHA-256 digest bytes
                    stored_hash = raw
                    if self.hash_master_password(master_password) == stored_hash:
                        # On successful legacy verification, transparently upgrade
                        try:
                            new_record = self._create_scrypt_master_record(master_password)
                            self._secure_write_text(hash_file, json.dumps(new_record))
                        except Exception:
                            # If upgrade fails, still allow login
                            pass
                        return True
                    return False
            except Exception as e:
                messagebox.showerror("Error", f"Failed to verify password: {str(e)}")
                return False
        else:
            # First time setup - validate password strength
            is_valid, message = self.validate_master_password_strength(master_password)
            if not is_valid:
                messagebox.showerror("Weak Password", message)
                return False
            
            try:
                record = self._create_scrypt_master_record(master_password)
                self._secure_write_text(hash_file, json.dumps(record))
                return True
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save password hash: {str(e)}")
                return False

    def check_session_status(self):
        """Check if session should be locked due to inactivity"""
        if self.is_locked:
            return False
        if time.time() - self.last_activity > self.session_timeout:
            self.lock_session()
            return False
        return True

    def refresh_password_list(self):
        """Refresh the password list display"""
        if not self.listbox:
            return
            
        self.listbox.delete(0, tk.END)
        search_term = self.search_var.get().lower() if self.search_var else ""
        
        # Filter and sort passwords
        filtered_sites = []
        for site in self.passwords.keys():
            if search_term in site.lower():
                filtered_sites.append(site)
        
        filtered_sites.sort()
        
        for site in filtered_sites:
            self.listbox.insert(tk.END, site)
        
        # Update count
        count = len(filtered_sites)
        total = len(self.passwords)
        if search_term:
            self.update_status(f"Showing {count} of {total} passwords")
        else:
            self.update_status(f"{total} passwords stored")

    def on_search_change(self):
        """Handle search box changes"""
        self.refresh_password_list()
        self.update_activity()

    def on_list_select(self, event):
        """Handle password list selection"""
        self.update_activity()
        selection = self.listbox.curselection()
        if selection:
            site = self.listbox.get(selection[0])
            self.quick_retrieve_password(site)

    def quick_retrieve_password(self, site):
        """Quickly retrieve and copy password to clipboard"""
        if not self.check_session_status():
            return
        
        if site in self.passwords:
            try:
                enc_password = self.passwords[site]
                decrypted_password = self.decrypt_password(self.key, enc_password)
                self.copy_to_clipboard(decrypted_password)
                self.update_status(f"Password for {site} copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")

    # --- GUI Functions ---
    def add_password(self):
        """Add a new password entry with strength checking"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        # Get site name
        site = simpledialog.askstring("Add Password", "Enter website/application name:")
        if not site:
            return
        
        # Check if site already exists
        if site in self.passwords:
            if not messagebox.askyesno("Site Exists", f"Password for {site} already exists. Update it?"):
                return
        
        # Get password with strength checking
        while True:
            password = simpledialog.askstring("Add Password", 
                f"Enter password for {site}:\n(Click OK to see strength analysis)", show="*")
            if not password:
                return
            
            # Show strength analysis
            score, strength, feedback = self.check_password_strength(password)
            
            feedback_text = f"Password Strength: {strength}\n"
            if feedback:
                feedback_text += "\nSuggestions:\n• " + "\n• ".join(feedback)
            
            if score >= 4:  # Good or better
                feedback_text += "\n\nThis password meets security standards!"
                if messagebox.askyesno("Password Strength", feedback_text + "\n\nUse this password?"):
                    break
            else:
                feedback_text += "\n\nConsider using a stronger password."
                choice = messagebox.askyesnocancel("Weak Password", 
                    feedback_text + "\n\nYes: Use anyway\nNo: Try again\nCancel: Exit")
                if choice is True:  # Use anyway
                    break
                elif choice is False:  # Try again
                    continue
                else:  # Cancel
                    return
        
        # Save password
        enc_password = self.encrypt_password(self.key, password)
        self.passwords[site] = enc_password.decode()
        self.save_passwords_to_file("passwords.json", self.passwords)
        self.refresh_password_list()
        self.update_status(f"Password for {site} saved!")

    def retrieve_password(self):
        """Retrieve and display a password"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        site = simpledialog.askstring("Retrieve Password", "Enter website/application name:")
        if not site:
            return
        
        if site in self.passwords:
            try:
                enc_password = self.passwords[site]
                decrypted_password = self.decrypt_password(self.key, enc_password)
                
                # Show password with copy option
                result = messagebox.askyesnocancel("Password Retrieved", 
                    f"Password for {site}: {decrypted_password}\n\nCopy to clipboard?")
                
                if result is True:  # Yes - copy to clipboard
                    self.copy_to_clipboard(decrypted_password)
                # If No or Cancel, just close dialog
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
        else:
            messagebox.showerror("Error", f"No password found for {site}.")

    def generate_password(self):
        """Generate a strong password with customizable options"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        # Create custom dialog for password generation
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Strong Password")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Length selection
        tk.Label(dialog, text="Password Length:", font=("Arial", 12)).pack(pady=10)
        length_var = tk.IntVar(value=16)
        length_scale = tk.Scale(dialog, from_=8, to=32, orient=tk.HORIZONTAL, 
                               variable=length_var, length=200)
        length_scale.pack(pady=5)
        
        # Password display
        tk.Label(dialog, text="Generated Password:", font=("Arial", 12)).pack(pady=(20,5))
        password_var = tk.StringVar()
        password_entry = tk.Entry(dialog, textvariable=password_var, width=40, 
                                 font=("Courier", 10), state="readonly")
        password_entry.pack(pady=5)
        
        # Strength display
        strength_var = tk.StringVar()
        strength_label = tk.Label(dialog, textvariable=strength_var, font=("Arial", 10))
        strength_label.pack(pady=5)
        
        def generate_new():
            length = length_var.get()
            password = self.generate_strong_password(length)
            password_var.set(password)
            score, strength, _ = self.check_password_strength(password)
            strength_var.set(f"Strength: {strength}")
            
            # Color code strength
            colors = ["red", "orange", "yellow", "lightgreen", "green", "darkgreen"]
            strength_label.config(fg=colors[min(score, 5)])
        
        # Buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Generate New", command=generate_new).pack(side=tk.LEFT, padx=5)
        
        def copy_password():
            password = password_var.get()
            if password:
                self.copy_to_clipboard(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        tk.Button(button_frame, text="Copy to Clipboard", command=copy_password).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Generate initial password
        generate_new()

    def view_saved_websites(self):
        """View all saved website/application names with details"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        if self.passwords:
            sites = sorted(self.passwords.keys())
            sites_text = f"Total passwords: {len(sites)}\n\n"
            sites_text += "\n".join(f"• {site}" for site in sites)
            
            # Create scrollable text window
            dialog = tk.Toplevel(self.root)
            dialog.title("Saved Passwords")
            dialog.geometry("400x500")
            dialog.transient(self.root)
            
            text_widget = tk.Text(dialog, wrap=tk.WORD, padx=10, pady=10)
            scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            text_widget.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            text_widget.insert("1.0", sites_text)
            text_widget.config(state="disabled")
        else:
            messagebox.showinfo("Saved Websites", "No websites/applications saved yet.")

    def delete_password(self):
        """Delete a password entry with confirmation"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        site = simpledialog.askstring("Delete Password", "Enter website/application name to delete:")
        if not site:
            return
        
        if site in self.passwords:
            if messagebox.askyesno("Confirm Deletion", 
                f"Are you sure you want to delete the password for {site}?\n\nThis action cannot be undone."):
                del self.passwords[site]
                self.save_passwords_to_file("passwords.json", self.passwords)
                self.refresh_password_list()
                self.update_status(f"Password for {site} deleted.")
        else:
            messagebox.showerror("Error", f"No password found for {site}.")

    def export_passwords(self):
        """Export passwords to an encrypted backup file protected by its own password"""
        if not self.check_session_status():
            return
        
        self.update_activity()

        if not self.passwords:
            messagebox.showinfo("Export", "No passwords to export.")
            return

        # Ask user for a backup password
        backup_password = simpledialog.askstring(
            "Backup Password",
            "Enter a password to protect the backup file:",
            show="*",
        )
        if not backup_password:
            return

        confirm_password = simpledialog.askstring(
            "Confirm Backup Password",
            "Re-enter the backup password:",
            show="*",
        )
        if backup_password != confirm_password:
            messagebox.showerror("Mismatch", "Backup passwords do not match.")
            return

        # Prepare payload with metadata and stored ciphertexts
        backup_payload = {
            "timestamp": time.time(),
            "version": "2.0",
            "count": len(self.passwords),
            "passwords": self.passwords,
        }
        plaintext = json.dumps(backup_payload).encode("utf-8")

        # Derive a key from the backup password
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend(),
        )
        backup_key = kdf.derive(backup_password.encode())

        aesgcm = AESGCM(backup_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        export_record = {
            "version": 1,
            "kdf": "scrypt",
            "n": 2**14,
            "r": 8,
            "p": 1,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

        data_dir = self.get_data_dir()
        filename = os.path.join(
            data_dir, f"password_backup_{int(time.time())}.mpmbackup"
        )

        try:
            self._secure_write_text(filename, json.dumps(export_record, indent=2))
            messagebox.showinfo(
                "Export Complete",
                f"Encrypted backup created at:\n{filename}\n\n"
                "Keep this file safe and remember the backup password.",
            )
            self.update_status(f"Exported {len(self.passwords)} passwords")
        except Exception as e:
            messagebox.showerror(
                "Export Failed", f"Failed to export encrypted backup: {str(e)}"
            )

    def import_passwords_from_backup(self):
        """Import passwords from an encrypted backup (.mpmbackup) file"""
        if not self.check_session_status():
            return

        self.update_activity()

        data_dir = self.get_data_dir()
        filepath = filedialog.askopenfilename(
            title="Select encrypted backup file",
            initialdir=data_dir,
            filetypes=[("Password Manager Backup", "*.mpmbackup"), ("All files", "*.*")],
        )
        if not filepath:
            return

        # Ask for backup password
        backup_password = simpledialog.askstring(
            "Backup Password",
            "Enter the password used to protect this backup:",
            show="*",
        )
        if not backup_password:
            return

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rec = json.load(f)

            salt = base64.b64decode(rec["salt"])
            nonce = base64.b64decode(rec["nonce"])
            ciphertext = base64.b64decode(rec["ciphertext"])

            n = rec.get("n", 2**14)
            r = rec.get("r", 8)
            p = rec.get("p", 1)

            kdf = Scrypt(
                salt=salt,
                length=32,
                n=n,
                r=r,
                p=p,
                backend=default_backend(),
            )
            backup_key = kdf.derive(backup_password.encode())

            aesgcm = AESGCM(backup_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            payload = json.loads(plaintext.decode("utf-8"))

            if not isinstance(payload, dict) or "passwords" not in payload:
                raise ValueError("Invalid backup format")

            imported_pwds = payload["passwords"] or {}
            if not isinstance(imported_pwds, dict):
                raise ValueError("Invalid passwords section in backup")

            # Merge into current passwords, overriding duplicates
            existing_count = len(self.passwords)
            imported_count = len(imported_pwds)

            self.passwords.update(imported_pwds)
            self.save_passwords_to_file("passwords.json", self.passwords)
            self.refresh_password_list()
            self.update_stats()

            messagebox.showinfo(
                "Import Complete",
                f"Imported {imported_count} entries from backup.\n"
                f"Vault now contains {len(self.passwords)} passwords.",
            )
            self.update_status(
                f"Imported {imported_count} passwords from encrypted backup"
            )
        except Exception as e:
            messagebox.showerror(
                "Import Failed",
                "Failed to import backup. The password may be incorrect or the "
                f"file may be corrupted.\n\nDetails: {str(e)}",
            )

    def lock_manually(self):
        """Manually lock the session"""
        self.lock_session()

    def authenticate_user(self):
        """Handle user authentication with retry logic"""
        while True:
            # Check if account is locked
            if self.is_account_locked():
                remaining_time = self.lockout_duration - (time.time() - self.last_lockout_time)
                messagebox.showerror("Account Locked", 
                    f"Account is locked. Try again in {int(remaining_time // 60)} minutes.")
                return False

            # Get master password
            master_password = simpledialog.askstring(
                "Master Password", 
                "Enter your master password:", 
                show="*"
            )
            
            if not master_password:
                return False
            
            if self.verify_master_password(master_password):
                self.failed_attempts = 0
                self.key = self.generate_key(master_password, self.salt)
                return True
            else:
                self.failed_attempts += 1
                if self.failed_attempts >= self.max_failed_attempts:
                    self.last_lockout_time = time.time()
                    messagebox.showerror("Account Locked", 
                        f"Too many failed attempts. Account locked for {self.lockout_duration // 60} minutes.")
                    return False
                else:
                    remaining = self.max_failed_attempts - self.failed_attempts
                    messagebox.showerror("Access Denied", 
                        f"Invalid master password. {remaining} attempts remaining.")

    def run(self):
        """Main application entry point"""
        # Initialize salt
        self.salt = self.get_salt()
        if not self.salt:
            return

        # Load existing passwords
        self.passwords = self.load_passwords_from_file("passwords.json")

        # Authenticate user
        if not self.authenticate_user():
            return
        
        # Start session
        self.update_activity()

        # Create the main window
        self.root = tk.Tk()
        self.root.title("Modern Password Manager")
        self.root.geometry("900x600")
        # Prevent resizing the window so small that controls become inaccessible
        self.root.minsize(800, 550)
        # Dark background for the root window
        self.root.configure(bg="#020617")
        
        # Bind window events to update activity
        self.root.bind('<Button-1>', lambda e: self.update_activity())
        self.root.bind('<Key>', lambda e: self.update_activity())

        # Create main layout
        self.create_main_interface()
        
        # Set window close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.safe_exit)

        # Run the main loop
        self.root.mainloop()

    def create_main_interface(self):
        """Create the main user interface (dark theme with tabs)"""
        # Dark theme palette
        bg_root = "#020617"
        bg_panel = "#020617"
        bg_card = "#0f172a"
        bg_card_alt = "#020617"
        border_color = "#1f2937"
        text_primary = "#e5e7eb"
        text_muted = "#9ca3af"
        accent_primary = "#2563eb"
        accent_success = "#22c55e"
        accent_warning = "#eab308"
        accent_danger = "#ef4444"
        accent_muted = "#4b5563"

        # Title bar
        title_frame = tk.Frame(self.root, bg="#020617", height=50)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)

        title_label = tk.Label(
            title_frame,
            text="Modern Password Manager",
            font=("Arial", 16, "bold"),
            fg=text_primary,
            bg="#020617",
        )
        title_label.pack(pady=12)

        # Status and timer bar
        status_frame = tk.Frame(self.root, bg="#030712", height=32)
        status_frame.pack(fill=tk.X)
        status_frame.pack_propagate(False)

        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=("Arial", 9),
            fg=text_muted,
            bg="#030712",
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=6)

        self.timer_label = tk.Label(
            status_frame,
            text="",
            font=("Arial", 9),
            fg=text_muted,
            bg="#030712",
        )
        self.timer_label.pack(side=tk.RIGHT, padx=10, pady=6)

        # Main content area with tabs
        main_frame = tk.Frame(self.root, bg=bg_panel)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "TNotebook",
            background=bg_panel,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=bg_card,
            foreground=text_muted,
            padding=(10, 6),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#111827")],
            foreground=[("selected", text_primary)],
        )

        # Shared dark button style for actions and tools
        style.configure(
            "Accent.TButton",
            background="#1f2937",
            foreground=text_primary,
            padding=(6, 4),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#374151"), ("pressed", "#111827")],
            foreground=[("disabled", "#6b7280")],
        )

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # ----- Vault tab -----
        vault_tab = tk.Frame(notebook, bg=bg_panel)
        notebook.add(vault_tab, text="Vault")

        vault_tab.columnconfigure(0, weight=3, uniform="vault")
        vault_tab.columnconfigure(1, weight=2, uniform="vault")
        vault_tab.rowconfigure(0, weight=1)

        # Left side: password vault
        left_container = tk.Frame(vault_tab, bg=bg_panel)
        left_container.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)

        left_frame = tk.LabelFrame(
            left_container,
            text="Password Vault",
            font=("Arial", 12, "bold"),
            bg=bg_card,
            fg=text_primary,
            bd=1,
            relief=tk.GROOVE,
        )
        left_frame.pack(fill=tk.BOTH, expand=True)

        # Search section
        search_frame = tk.Frame(left_frame, bg=bg_card)
        search_frame.pack(fill=tk.X, padx=12, pady=10)

        tk.Label(
            search_frame,
            text="Search passwords:",
            font=("Arial", 10, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W)

        self.search_var = tk.StringVar()
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=("Arial", 10),
            bg=bg_card_alt,
            fg=text_primary,
            insertbackground=text_primary,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=border_color,
        )
        search_entry.pack(fill=tk.X, pady=(6, 0))
        search_entry.bind("<KeyRelease>", lambda event: self.on_search_change())

        # Password list
        list_frame = tk.Frame(left_frame, bg=bg_card)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 12))

        tk.Label(
            list_frame,
            text="Saved passwords (double-click to copy):",
            font=("Arial", 10, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W, pady=(0, 4))

        list_container = tk.Frame(list_frame, bg=bg_card)
        list_container.pack(fill=tk.BOTH, expand=True)

        self.listbox = tk.Listbox(
            list_container,
            font=("Arial", 10),
            selectmode=tk.SINGLE,
            bg=bg_card_alt,
            fg=text_primary,
            selectbackground=accent_primary,
            selectforeground="white",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=border_color,
            activestyle="none",
        )
        scrollbar_list = ttk.Scrollbar(
            list_container, orient="vertical", command=self.listbox.yview
        )
        self.listbox.configure(yscrollcommand=scrollbar_list.set)

        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar_list.pack(side="right", fill="y")
        self.listbox.bind("<Double-Button-1>", self.on_list_select)

        # Right side: actions & stats (non-scrollable container)
        right_container = tk.Frame(vault_tab, bg=bg_panel)
        right_container.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=4)

        actions_frame = tk.LabelFrame(
            right_container,
            text="Actions",
            font=("Arial", 12, "bold"),
            bg=bg_card,
            fg=text_primary,
            bd=1,
            relief=tk.GROOVE,
        )
        actions_frame.pack(fill=tk.BOTH, expand=True)

        def create_button(parent, text, command):
            return ttk.Button(
                parent,
                text=text,
                command=command,
                style="Accent.TButton",
            )

        inner = tk.Frame(actions_frame, bg=bg_card)
        inner.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Password operations
        tk.Label(
            inner,
            text="Password Operations",
            font=("Arial", 11, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W, pady=(0, 6))

        create_button(inner, "Add New Password", self.add_password).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Retrieve Password", self.retrieve_password).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Generate Strong Password", self.generate_password).pack(
            fill=tk.X, pady=3
        )

        # Management
        tk.Label(
            inner,
            text="Management",
            font=("Arial", 11, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W, pady=(16, 6))

        create_button(inner, "View All Passwords", self.view_saved_websites).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Delete Password", self.delete_password).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Export Backup", self.export_passwords).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Import Backup", self.import_passwords_from_backup).pack(
            fill=tk.X, pady=3
        )

        # Security
        tk.Label(
            inner,
            text="Security",
            font=("Arial", 11, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W, pady=(16, 6))

        create_button(inner, "Lock Session", self.lock_manually).pack(
            fill=tk.X, pady=3
        )
        create_button(inner, "Exit Application", self.safe_exit).pack(
            fill=tk.X, pady=3
        )

        # Stats at the bottom
        stats_frame = tk.LabelFrame(
            inner,
            text="Statistics",
            font=("Arial", 10, "bold"),
            bg=bg_card,
            fg=text_muted,
            bd=1,
            relief=tk.GROOVE,
        )
        stats_frame.pack(fill=tk.X, pady=(16, 0))

        self.stats_label = tk.Label(
            stats_frame,
            text="",
            font=("Arial", 9),
            bg=bg_card,
            fg=text_primary,
            justify=tk.LEFT,
        )
        self.stats_label.pack(pady=8, padx=8, anchor="w")

        # ----- Tools tab (simple utilities) -----
        tools_tab = tk.Frame(notebook, bg=bg_panel)
        notebook.add(tools_tab, text="Tools")

        tools_tab.columnconfigure(0, weight=1)
        tools_tab.rowconfigure(0, weight=1)

        tools_frame = tk.LabelFrame(
            tools_tab,
            text="Utilities",
            font=("Arial", 12, "bold"),
            bg=bg_card,
            fg=text_primary,
            bd=1,
            relief=tk.GROOVE,
        )
        tools_frame.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        tools_inner = tk.Frame(tools_frame, bg=bg_card)
        tools_inner.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        tk.Label(
            tools_inner,
            text="Quick Password Tools",
            font=("Arial", 11, "bold"),
            bg=bg_card,
            fg=text_muted,
        ).pack(anchor=tk.W, pady=(0, 8))

        tk.Label(
            tools_inner,
            text="Use these helpers for generating and evaluating passwords.",
            font=("Arial", 9),
            bg=bg_card,
            fg=text_muted,
            wraplength=360,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 12))

        create_button(
            tools_inner, "Open Strong Password Generator", self.generate_password
        ).pack(fill=tk.X, pady=4)

        create_button(
            tools_inner, "Export Encrypted Backup", self.export_passwords
        ).pack(fill=tk.X, pady=4)

        create_button(
            tools_inner, "Import Encrypted Backup", self.import_passwords_from_backup
        ).pack(fill=tk.X, pady=4)

        # Initialize display
        self.refresh_password_list()
        self.update_stats()

    def update_stats(self):
        """Update statistics display"""
        if self.stats_label:
            total = len(self.passwords)
            stats_text = f"Total passwords: {total}\n"
            if total > 0:
                avg_length = sum(len(site) for site in self.passwords.keys()) / total
                stats_text += f"Avg site name length: {avg_length:.1f}\n"
                stats_text += f"Security: AES-256 encryption"
            else:
                stats_text += "No passwords stored yet"
            
            self.stats_label.config(text=stats_text)

    def safe_exit(self):
        """Safely exit the application"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?\n\nAll sensitive data will be cleared from memory."):
            if self.root:
                if self.session_timer is not None:
                    try:
                        self.root.after_cancel(self.session_timer)
                    except Exception:
                        pass
                if self.clipboard_timer is not None:
                    try:
                        self.root.after_cancel(self.clipboard_timer)
                    except Exception:
                        pass
            self.clear_sensitive_data()
            if self.root:
                self.root.quit()

# ---- Lightweight CLI for password strength (non-GUI) ----
def _strength_score(pw: str) -> int:
    """Very simple heuristic: 0–4 score."""
    import re
    score = 0
    if len(pw) >= 12: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"[^\w\s]", pw): score += 1
    return min(score, 4)

def _strength_label(score: int) -> str:
    return ["very weak","weak","okay","strong","very strong"][score]

def main() -> None:
    """Entry point for both CLI utilities and the GUI application."""
    import argparse

    parser = argparse.ArgumentParser(description="Password Manager utilities")
    parser.add_argument(
        "--check-strength",
        metavar="PASSWORD",
        help="Print strength of a password and exit",
    )
    args = parser.parse_args()

    if args.check_strength:
        score = _strength_score(args.check_strength)
        print(_strength_label(score))
        return

    app = ModernPasswordManager()
    app.run()


if __name__ == "__main__":
    main()