import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Key Derivation Function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt File
def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    enc_file_path = f"{file_path}.enc"
    with open(enc_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    return enc_file_path

# Decrypt File
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        dec_file_path = file_path.replace('.enc', '.dec')
        with open(dec_file_path, 'wb') as f:
            f.write(plaintext)
        return dec_file_path
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.")

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("400x300")
        
        # File Selection
        self.file_label = tk.Label(root, text="Select File:")
        self.file_label.pack(pady=5)
        self.file_entry = tk.Entry(root, width=40)
        self.file_entry.pack(pady=5)
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)
        
        # Password
        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.pack(pady=5)

        # Encrypt Button
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_action, bg="green", fg="white")
        self.encrypt_button.pack(pady=10)

        # Decrypt Button
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_action, bg="blue", fg="white")
        self.decrypt_button.pack(pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def encrypt_action(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        try:
            enc_file = encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File encrypted: {enc_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        try:
            dec_file = decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File decrypted: {dec_file}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

# Main Function
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()