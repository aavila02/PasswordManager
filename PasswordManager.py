import os
import json
import base64
import hashlib
import time
import re
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from threading import Timer
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
        if self.session_timer:
            self.session_timer.cancel()
        self.session_timer = Timer(self.session_timeout, self.lock_session)
        self.session_timer.start()
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
                # Clear clipboard after 30 seconds
                if self.clipboard_timer:
                    self.clipboard_timer.cancel()
                self.clipboard_timer = Timer(30, self.clear_clipboard)
                self.clipboard_timer.start()
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
            # Add metadata
            data = {
                "version": "2.0",
                "created": time.time(),
                "passwords": passwords
            }
            with open(filename, 'w') as file:
                json.dump(data, file, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {str(e)}")

    def load_passwords_from_file(self, filename: str) -> dict:
        """Load encrypted passwords from file"""
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as file:
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
        salt_file = "salt.bin"
        if os.path.exists(salt_file):
            try:
                with open(salt_file, 'rb') as file:
                    return file.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read salt: {str(e)}")
                return None
        else:
            salt = os.urandom(16)
            try:
                with open(salt_file, 'wb') as file:
                    file.write(salt)
                return salt
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create salt: {str(e)}")
                return None

    def hash_master_password(self, master_password: str) -> bytes:
        """Hash master password using SHA-256"""
        return hashlib.sha256(master_password.encode()).digest()

    def verify_master_password(self, master_password: str) -> bool:
        """Verify master password against stored hash"""
        hashed_password = self.hash_master_password(master_password)
        hash_file = "master_hash.bin"
        
        if os.path.exists(hash_file):
            try:
                with open(hash_file, "rb") as f:
                    stored_hash = f.read()
                return hashed_password == stored_hash
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
                with open(hash_file, "wb") as f:
                    f.write(hashed_password)
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
        """Export passwords to encrypted backup file"""
        if not self.check_session_status():
            return
        
        self.update_activity()
        
        if not self.passwords:
            messagebox.showinfo("Export", "No passwords to export.")
            return
        
        # Simple export to JSON (for demo - in production, this would be more secure)
        backup_data = {
            "timestamp": time.time(),
            "version": "2.0",
            "count": len(self.passwords),
            "passwords": self.passwords
        }
        
        filename = f"password_backup_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(backup_data, f, indent=2)
            messagebox.showinfo("Export Complete", 
                f"Passwords exported to {filename}\n\nKeep this file secure!")
            self.update_status(f"Exported {len(self.passwords)} passwords")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export passwords: {str(e)}")

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
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
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
        """Create the main user interface"""
        # Title
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=50)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="Modern Password Manager", 
                             font=("Arial", 16, "bold"), fg="white", bg="#2c3e50")
        title_label.pack(pady=12)

        # Status and timer frame
        status_frame = tk.Frame(self.root, bg="#34495e", height=35)
        status_frame.pack(fill=tk.X)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                   font=("Arial", 9), fg="white", bg="#34495e")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=8)
        
        self.timer_label = tk.Label(status_frame, text="", 
                                  font=("Arial", 9), fg="white", bg="#34495e")
        self.timer_label.pack(side=tk.RIGHT, padx=10, pady=8)

        # Main content area
        main_frame = tk.Frame(self.root, bg="#f8f9fa")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Left panel - Password list and search
        left_frame = tk.LabelFrame(main_frame, text="Password Vault", 
                                 font=("Arial", 12, "bold"), bg="white", fg="#2c3e50",
                                 relief=tk.GROOVE, bd=2)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Search section
        search_frame = tk.Frame(left_frame, bg="white")
        search_frame.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(search_frame, text="Search passwords:", 
                font=("Arial", 10, "bold"), bg="white", fg="#2c3e50").pack(anchor=tk.W)
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                              font=("Arial", 10), width=40, bg="white", fg="black",
                              relief=tk.SUNKEN, bd=1)
        search_entry.pack(fill=tk.X, pady=(5, 0))
        search_entry.bind('<KeyRelease>', lambda event: self.on_search_change())

        # Password list
        list_frame = tk.Frame(left_frame, bg="white")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        tk.Label(list_frame, text="Saved passwords (double-click to copy):", 
                font=("Arial", 10, "bold"), bg="white", fg="#2c3e50").pack(anchor=tk.W, pady=(0, 5))
        
        # Listbox with scrollbar
        list_container = tk.Frame(list_frame, bg="white")
        list_container.pack(fill=tk.BOTH, expand=True)
        
        self.listbox = tk.Listbox(list_container, font=("Arial", 10), 
                                 selectmode=tk.SINGLE, height=20,
                                 bg="white", fg="black", 
                                 selectbackground="#3498db", selectforeground="white",
                                 relief=tk.SUNKEN, bd=1)
        scrollbar_list = ttk.Scrollbar(list_container, orient="vertical", 
                                     command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scrollbar_list.set)
        
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar_list.pack(side="right", fill="y")
        
        self.listbox.bind('<Double-Button-1>', self.on_list_select)

        # Right panel - Actions
        right_frame = tk.LabelFrame(main_frame, text="Actions", 
                                  font=("Arial", 12, "bold"), bg="white", fg="#2c3e50", 
                                  width=280, relief=tk.GROOVE, bd=2)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        right_frame.pack_propagate(False)

        # Actions section
        actions_frame = tk.Frame(right_frame, bg="white")
        actions_frame.pack(fill=tk.X, padx=15, pady=15)

        # Create styled buttons with better contrast
        def create_button(parent, text, command, bg_color="#3498db", text_color="white"):
            btn = tk.Button(parent, text=text, command=command,
                          font=("Arial", 10, "bold"), width=26, height=2,
                          bg=bg_color, fg=text_color, relief=tk.RAISED, bd=2,
                          cursor="hand2", activebackground="#2980b9", 
                          activeforeground="white")
            return btn

        # Primary actions
        tk.Label(actions_frame, text="Password Operations:", 
                font=("Arial", 11, "bold"), bg="white", fg="#2c3e50").pack(anchor=tk.W, pady=(0, 8))

        add_btn = create_button(actions_frame, "Add New Password", self.add_password, "#3498db")
        add_btn.pack(pady=3, fill=tk.X)

        retrieve_btn = create_button(actions_frame, "Retrieve Password", self.retrieve_password, "#27ae60")
        retrieve_btn.pack(pady=3, fill=tk.X)

        generate_btn = create_button(actions_frame, "Generate Strong Password", self.generate_password, "#9b59b6")
        generate_btn.pack(pady=3, fill=tk.X)

        # Management actions
        tk.Label(actions_frame, text="Management:", 
                font=("Arial", 11, "bold"), bg="white", fg="#2c3e50").pack(anchor=tk.W, pady=(20, 8))

        view_btn = create_button(actions_frame, "View All Passwords", self.view_saved_websites, "#34495e")
        view_btn.pack(pady=3, fill=tk.X)

        delete_btn = create_button(actions_frame, "Delete Password", self.delete_password, "#e74c3c")
        delete_btn.pack(pady=3, fill=tk.X)

        export_btn = create_button(actions_frame, "Export Backup", self.export_passwords, "#f39c12")
        export_btn.pack(pady=3, fill=tk.X)

        # Security actions
        tk.Label(actions_frame, text="Security:", 
                font=("Arial", 11, "bold"), bg="white", fg="#2c3e50").pack(anchor=tk.W, pady=(20, 8))

        lock_btn = create_button(actions_frame, "Lock Session", self.lock_manually, "#95a5a6")
        lock_btn.pack(pady=3, fill=tk.X)

        exit_btn = create_button(actions_frame, "Exit Application", self.safe_exit, "#7f8c8d")
        exit_btn.pack(pady=3, fill=tk.X)

        # Statistics section
        stats_frame = tk.LabelFrame(right_frame, text="Statistics", 
                                  font=("Arial", 10, "bold"), bg="white", fg="#2c3e50",
                                  relief=tk.GROOVE, bd=1)
        stats_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.stats_label = tk.Label(stats_frame, text="", 
                                  font=("Arial", 9), bg="white", fg="#2c3e50", justify=tk.LEFT)
        self.stats_label.pack(pady=10, padx=10)

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
            if self.session_timer:
                self.session_timer.cancel()
            if self.clipboard_timer:
                self.clipboard_timer.cancel()
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

if __name__ == "__main__":
    try:
        import argparse
        parser = argparse.ArgumentParser(description="Password Manager utilities")
        parser.add_argument("--check-strength", metavar="PASSWORD", help="Print strength of a password and exit")
        args, _ = parser.parse_known_args()
        if args.check_strength:
            s = _strength_score(args.check_strength)
            print(_strength_label(s))
            raise SystemExit(0)
    except Exception:
        # Fall through to your existing GUI startup if present
        pass

if __name__ == "__main__":
    # Check if pyperclip is available, install if needed
    try:
        import pyperclip
    except ImportError:
        print("Installing required dependency: pyperclip")
        import subprocess
        subprocess.check_call(["pip", "install", "pyperclip"])
        import pyperclip
    
    app = ModernPasswordManager()
    app.run()