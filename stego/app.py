import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
from stegano import lsb

class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryption & Decryption")
        self.geometry("700x550")
        self.resizable(False, False)
        self.configure(bg="#2c3e50")
        
        # Title
        tk.Label(self, text="Image Encryption & Decryption", font=("Arial", 20, "bold"), fg="#ecf0f1", bg="#2c3e50").pack(pady=20)
        
        # Frame for inputs
        frame = tk.Frame(self, bg="#34495e", padx=20, pady=20)
        frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        tk.Label(frame, text="Enter encryption password:", font=("Arial", 12), fg="#ecf0f1", bg="#34495e").pack(pady=5)
        self.password_entry = tk.Entry(frame, width=45, font=("Arial", 12), bd=3, show="*")
        self.password_entry.pack(pady=5)
        
        # Buttons
        self.encrypt_button = tk.Button(frame, text="Encrypt & Hide Image", font=("Arial", 12, "bold"), bg="#16a085", fg="white", bd=0, width=30, command=self.encrypt_image)
        self.encrypt_button.pack(pady=10)
        
        self.decrypt_button = tk.Button(frame, text="Decrypt & Reveal Image", font=("Arial", 12, "bold"), bg="#e74c3c", fg="white", bd=0, width=30, command=self.decrypt_image)
        self.decrypt_button.pack(pady=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=500, mode='determinate')
        self.progress.pack(pady=10)
        
    def encrypt_image(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        image_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        if not image_path:
            return
        
        with open(image_path, "rb") as image_file:
            image_bytes = image_file.read()
        
        encrypted_image = self.encrypt_data(image_bytes, password)
        secret_message = encrypted_image.hex()
        encoded_image = lsb.hide(image_path, secret_message)
        
        output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not output_image_path:
            return
        
        self.progress['value'] = 50
        self.update_idletasks()
        encoded_image.save(output_image_path)
        self.progress['value'] = 100
        messagebox.showinfo("Success", "Image encrypted and hidden successfully!")
        
    def encrypt_data(self, data, password):
        key = self.derive_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = data + (16 - len(data) % 16) * b'\x00'
        return encryptor.update(padded_data) + encryptor.finalize()
        
    def derive_key(self, password):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(password.encode())
        return digest.finalize()
        
    def decrypt_image(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        encrypted_image_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("PNG Image", "*.png")])
        if not encrypted_image_path:
            return
        
        secret_message = lsb.reveal(encrypted_image_path)
        if secret_message is None:
            messagebox.showerror("Error", "No hidden message found in the image")
            return
        
        encrypted_data = bytes.fromhex(secret_message)
        decrypted_image = self.decrypt_data(encrypted_data, password)
        
        decrypted_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not decrypted_image_path:
            return
        
        self.progress['value'] = 50
        self.update_idletasks()
        with open(decrypted_image_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_image)
        self.progress['value'] = 100
        self.open_image(decrypted_image_path)
        messagebox.showinfo("Success", "Image decrypted successfully!")
        
    def decrypt_data(self, encrypted_data, password):
        key = self.derive_key(password)
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()
        
    def open_image(self, image_path):
        try:
            img = Image.open(image_path)
            img.show()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open the image: {str(e)}")

if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
