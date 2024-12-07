import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
import os
import hashlib


# Initialize socket
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("mycert.crt")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(client_socket)
ssock.connect(('127.0.0.1', 12345))


# Function to generate RSA keys
def generate_rsa_keys(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_dir = f"/Users/seifelmougy/Documents/file_server_storage_keys/{username}"
    os.makedirs(key_dir, exist_ok=True)

    private_file = os.path.join(key_dir, f"{username}_private.pem")
    public_file = os.path.join(key_dir, f"{username}_public.pem")

    with open(private_file, "wb") as priv_file:
        priv_file.write(private_pem)

    with open(public_file, "wb") as pub_file:
        pub_file.write(public_pem)

    return public_file


# Tkinter App
class SecureFileClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Client")
        self.root.geometry("400x300")
        self.username = ""
        self.build_login_page()

    def build_login_page(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Secure File Client Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack(pady=10)
        tk.Button(self.root, text="Sign Up", command=self.signup).pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        credentials = f"2:{username}:{password}"
        ssock.send(credentials.encode("utf-8"))

        response = ssock.recv(1024).decode("utf-8")
        if "authentication successful" in response.lower():
            self.username = username
            messagebox.showinfo("Login", "Login successful!")
            self.build_main_menu()
        else:
            messagebox.showerror("Login Failed", response)

    def signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        credentials = f"1:{username}:{password}"
        ssock.send(credentials.encode("utf-8"))

        response = ssock.recv(1024).decode("utf-8")
        if "successful" in response.lower():
            generate_rsa_keys(username)
            messagebox.showinfo("Sign Up", "Account created successfully!")
        else:
            messagebox.showerror("Sign Up Failed", response)

    def build_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Welcome, {self.username}", font=("Arial", 16)).pack(pady=10)

        tk.Button(self.root, text="Upload File", command=self.upload_file).pack(pady=5)
        tk.Button(self.root, text="Download File", command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="List Files", command=self.list_files).pack(pady=5)
        tk.Button(self.root, text="Logout", command=self.build_login_page).pack(pady=5)

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file:
            file_data = file.read()

        file_hash = hashlib.sha256(file_data).hexdigest()

        private_key_path = f"/Users/seifelmougy/Documents/file_server_storage_keys/{self.username}/{self.username}_private.pem"
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        signature = private_key.sign(
            file_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Send file to server
        ssock.send(f"{file_name}:{file_data.decode('latin-1')}".encode("utf-8"))
        ssock.send(signature)
        ssock.send(file_hash.encode("utf-8"))

        response = ssock.recv(1024).decode("utf-8")
        messagebox.showinfo("Upload", response)

    def download_and_decrypt_file():
        try:
            # Get the username and file name from the GUI
            username = username_entry.get().strip()
            desired_file_name = filename_entry.get().strip()

            if not username or not desired_file_name:
                messagebox.showerror("Error", "Username and filename cannot be empty!")
                return

            # Load the private key
            private_key_path = f"/Users/seifelmougy/Documents/file_server_storage_keys/{username}/{username}_private.pem"
            if not os.path.exists(private_key_path):
                messagebox.showerror("Error", "Private key not found!")
                return

            with open(private_key_path, "rb") as key_file:
                private_key = load_pem_private_key(
                    key_file.read(),
                    password=None,
                )

            # Connect to the server (adjust IP and port as needed)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(("127.0.0.1", 12345))  # Replace with your server's IP and port
                client_socket.send(desired_file_name.encode("utf-8"))

                # Receive the encrypted file size
                encrypted_file_size = int(client_socket.recv(1024).decode("utf-8"))
                client_socket.send(b"SIZE RECEIVED")  # Acknowledge size receipt

                # Receive the encrypted data in chunks
                downloaded_file_data = b""
                while len(downloaded_file_data) < encrypted_file_size:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    downloaded_file_data += chunk

                if not downloaded_file_data:
                    messagebox.showerror("Error", "File not found on the server or no data received.")
                    return

                # Decrypt the file
                decrypted_data = private_key.decrypt(
                    downloaded_file_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Ask user for save location
                save_path = filedialog.askdirectory()
                if not save_path:
                    messagebox.showinfo("Info", "File saving canceled.")
                    return

                file_save_path = os.path.join(save_path, desired_file_name)
                with open(file_save_path, "wb") as file:
                    file.write(decrypted_data)

                # Compute the hash of the downloaded file
                decrypted_file_hash = hashlib.sha256(decrypted_data).hexdigest()

                # Receive the file hash from the server
                file_hash_received = client_socket.recv(1024).decode("utf-8")
                if decrypted_file_hash == file_hash_received:
                    messagebox.showinfo("Success", f"File '{desired_file_name}' downloaded and verified successfully.")
                else:
                    messagebox.showwarning("Warning", "Hash mismatch! File integrity may be compromised.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def list_files(self):
        ssock.send("2".encode("utf-8"))
        response = ssock.recv(1024).decode("utf-8")
        messagebox.showinfo("Files", response)


# Start GUI
root = tk.Tk()
app = SecureFileClientApp(root)
root.mainloop()
