import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import hmac
import json
from typing import Tuple

class AdvancedEncrypter:
    def __init__(self):
        self.backend = default_backend()
    
    def _derive_key(self, password: str, salt: bytes, iterations: int = 100000) -> Tuple[bytes, bytes]:
        """Derive encryption and authentication keys from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        key_material = kdf.derive(password.encode('utf-8'))
        return key_material[:32], key_material[32:]
    
    def _generate_nonce(self) -> bytes:
        """Generate cryptographically secure random nonce"""
        return secrets.token_bytes(16)
    
    def encrypt(self, plaintext: str, password: str = "1234") -> str:
        """Encrypt plaintext"""
        if not plaintext.strip():
            raise ValueError("Please enter text to encrypt")
        if not password.strip():
            raise ValueError("Please enter an encryption password")
            
        salt = secrets.token_bytes(32)
        nonce = self._generate_nonce()
        enc_key, auth_key = self._derive_key(password, salt)
        iv = secrets.token_bytes(16)
        
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(salt + nonce)
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        
        hmac_obj = hmac.new(auth_key, salt + nonce + iv + ciphertext + tag, hashlib.sha512)
        hmac_digest = hmac_obj.digest()
        
        encrypted_package = {
            'salt': base64.b64encode(salt).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'iv': base64.b64encode(iv).decode('ascii'),
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'tag': base64.b64encode(tag).decode('ascii'),
            'hmac': base64.b64encode(hmac_digest).decode('ascii'),
            'version': '1.0'
        }
        
        return base64.b64encode(json.dumps(encrypted_package).encode('ascii')).decode('ascii')
    
    def decrypt(self, encrypted_data: str, password: str = "1234") -> str:
        """Decrypt previously encrypted data"""
        if not encrypted_data.strip():
            raise ValueError("Please enter encrypted text to decrypt")
        if not password.strip():
            raise ValueError("Please enter the decryption password")
            
        try:
            package_json = base64.b64decode(encrypted_data).decode('ascii')
            package = json.loads(package_json)
            
            salt = base64.b64decode(package['salt'])
            nonce = base64.b64decode(package['nonce'])
            iv = base64.b64decode(package['iv'])
            ciphertext = base64.b64decode(package['ciphertext'])
            tag = base64.b64decode(package['tag'])
            received_hmac = base64.b64decode(package['hmac'])
            
            enc_key, auth_key = self._derive_key(password, salt)
            
            hmac_obj = hmac.new(auth_key, salt + nonce + iv + ciphertext + tag, hashlib.sha512)
            expected_hmac = hmac_obj.digest()
            
            if not hmac.compare_digest(expected_hmac, received_hmac):
                raise ValueError("HMAC verification failed - wrong password or tampered data")
            
            cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(salt + nonce)
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

class EncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encrypter/Decrypter")
        self.root.geometry("900x750")
        self.root.configure(bg='#2b2b2b')
        
        self.encrypter = AdvancedEncrypter()
        self.default_password = "1234"  # Default password
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background='#2b2b2b')
        style.configure('TLabel', background='#2b2b2b', foreground='white', font=('Arial', 10))
        style.configure('TButton', font=('Arial', 10), padding=6)
        style.configure('Header.TLabel', font=('Arial', 16, 'bold'), foreground='#4CAF50')
        style.configure('TEntry', font=('Arial', 10), padding=5)
        style.configure('Info.TLabel', foreground='#ff9800', font=('Arial', 9))
        
        style.map('TButton',
                 background=[('active', '#45a049')],
                 foreground=[('active', 'white')])
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Encryption Tool", style='Header.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Default password info
        info_label = ttk.Label(main_frame, 
                              text=f"Default Password: {self.default_password} (You can change this)", 
                              style='Info.TLabel')
        info_label.pack(pady=(0, 10))
        
        # Encryption Section
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption", padding="15")
        enc_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(enc_frame, text="Text to Encrypt:").pack(anchor=tk.W)
        self.encrypt_text = scrolledtext.ScrolledText(enc_frame, height=6, width=80, font=('Arial', 10))
        self.encrypt_text.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Label(enc_frame, text="Encryption Password:").pack(anchor=tk.W)
        self.encrypt_password = ttk.Entry(enc_frame, show="*", width=50)
        self.encrypt_password.pack(fill=tk.X, pady=(5, 10))
        self.encrypt_password.insert(0, self.default_password)  # Set default password
        
        encrypt_btn = ttk.Button(enc_frame, text="Encrypt Text", command=self.encrypt_text_command)
        encrypt_btn.pack(pady=(5, 5))
        
        ttk.Label(enc_frame, text="Encrypted Result:").pack(anchor=tk.W, pady=(15, 5))
        self.encrypted_result = scrolledtext.ScrolledText(enc_frame, height=4, width=80, font=('Courier', 9))
        self.encrypted_result.pack(fill=tk.X, pady=(5, 5))
        
        # Decryption Section
        dec_frame = ttk.LabelFrame(main_frame, text="Decryption", padding="15")
        dec_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(dec_frame, text="Text to Decrypt:").pack(anchor=tk.W)
        self.decrypt_text = scrolledtext.ScrolledText(dec_frame, height=6, width=80, font=('Arial', 10))
        self.decrypt_text.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Label(dec_frame, text="Decryption Password:").pack(anchor=tk.W)
        self.decrypt_password = ttk.Entry(dec_frame, show="*", width=50)
        self.decrypt_password.pack(fill=tk.X, pady=(5, 10))
        self.decrypt_password.insert(0, self.default_password)  # Set default password
        
        decrypt_btn = ttk.Button(dec_frame, text="Decrypt Text", command=self.decrypt_text_command)
        decrypt_btn.pack(pady=(5, 5))
        
        ttk.Label(dec_frame, text="Decrypted Result:").pack(anchor=tk.W, pady=(15, 5))
        self.decrypted_result = scrolledtext.ScrolledText(dec_frame, height=4, width=80, font=('Arial', 10))
        self.decrypted_result.pack(fill=tk.X, pady=(5, 5))
        
        # Utility buttons frame
        util_frame = ttk.Frame(main_frame)
        util_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(util_frame, text="Copy Encrypted", command=self.copy_encrypted).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(util_frame, text="Paste to Decrypt", command=self.paste_to_decrypt).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(util_frame, text="Use Default Password", command=self.use_default_password).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(util_frame, text="Clear All", command=self.clear_all).pack(side=tk.LEFT)
        
        # Security info
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(20, 0))
        
        info_text = """
Security Features:
• AES-256 Encryption (Military Grade)
• PBKDF2 Key Derivation with 100,000 iterations
• HMAC-SHA512 Integrity Verification
• GCM Mode for Authenticated Encryption
• Random Salts and IVs for each encryption
• Protection against tampering and brute-force attacks
• Default Password: 1234 (Change for better security)
        """
        info_label = ttk.Label(info_frame, text=info_text, justify=tk.LEFT, foreground='#cccccc')
        info_label.pack(anchor=tk.W)
        
    def encrypt_text_command(self):
        try:
            plaintext = self.encrypt_text.get("1.0", tk.END).strip()
            password = self.encrypt_password.get().strip()
            
            if not password:
                password = self.default_password
                
            encrypted = self.encrypter.encrypt(plaintext, password)
            
            self.encrypted_result.delete("1.0", tk.END)
            self.encrypted_result.insert("1.0", encrypted)
            
            messagebox.showinfo("Success", "Text encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt_text_command(self):
        try:
            encrypted_text = self.decrypt_text.get("1.0", tk.END).strip()
            password = self.decrypt_password.get().strip()
            
            if not password:
                password = self.default_password
                
            decrypted = self.encrypter.decrypt(encrypted_text, password)
            
            self.decrypted_result.delete("1.0", tk.END)
            self.decrypted_result.insert("1.0", decrypted)
            
            messagebox.showinfo("Success", "Text decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
    
    def copy_encrypted(self):
        encrypted_text = self.encrypted_result.get("1.0", tk.END).strip()
        if encrypted_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(encrypted_text)
            messagebox.showinfo("Copied", "Encrypted text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No encrypted text to copy")
    
    def paste_to_decrypt(self):
        try:
            clipboard_text = self.root.clipboard_get()
            self.decrypt_text.delete("1.0", tk.END)
            self.decrypt_text.insert("1.0", clipboard_text)
        except:
            messagebox.showwarning("Warning", "No text in clipboard to paste")
    
    def use_default_password(self):
        """Set both password fields to default password"""
        self.encrypt_password.delete(0, tk.END)
        self.encrypt_password.insert(0, self.default_password)
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_password.insert(0, self.default_password)
        messagebox.showinfo("Default Password", f"Both password fields set to: {self.default_password}")
    
    def clear_all(self):
        self.encrypt_text.delete("1.0", tk.END)
        self.encrypt_password.delete(0, tk.END)
        self.encrypt_password.insert(0, self.default_password)
        self.encrypted_result.delete("1.0", tk.END)
        self.decrypt_text.delete("1.0", tk.END)
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_password.insert(0, self.default_password)
        self.decrypted_result.delete("1.0", tk.END)

def main():
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()