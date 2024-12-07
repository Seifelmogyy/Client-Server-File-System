import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import hashlib
import re

#Client Socket Server
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("mycert.crt")
client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ssock = context.wrap_socket(client_socket) 
ssock.connect(('127.0.0.1',12345))

def generate_rsa_keys(username):
    """
    Generates RSA public and private keys for a given username and saves them to PEM files.
    """
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key to PEM file
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save public key to PEM file
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    nested_directory = f"/Users/seifelmougy/Documents/file_server_storage_keys/{username}"
    os.makedirs(nested_directory)
    os.chdir(nested_directory)

    # Save to files with username-based filenames
    private_filename = f"{username}_private.pem"
    public_filename = f"{username}_public.pem"

    with open(private_filename, "wb") as private_file:
        private_file.write(private_pem)

    with open(public_filename, "wb") as public_file:
        public_file.write(public_pem)

    print(f"RSA keys saved for {username}: {private_filename}, {public_filename}")
    return public_filename

def validate_password(password):
    """Validates password to meet the required criteria."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):  # Check for uppercase
        return False
    if not re.search(r"[a-z]", password):  # Check for lowercase
        return False
    if not re.search(r"[0-9]", password):  # Check for digit
        return False
    if not re.search(r"[\W_]", password):  # Check for special character
        return False
    return True


def main():
        

        authenticated = False  # Track if the user has successfully authenticated

        #Authentication
        while True:
            print("1. Sign Up")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ")
            if choice == "1":
                print("\n--- Sign Up ---")
                username = input("Enter a new username: ")
                while True:
                    print("\n--- Password must be at least 8 characters long, 1 uppercase, 1 lowercase, 1 digit, and 1 special character ---")
                    password = input("Enter a new password: ")
                    if validate_password(password):
                        break
                    else:
                        print("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character. Please try again.")

                # Generate and save RSA keys for the user
                public_filename = generate_rsa_keys(username)

                # Send action and credentials to the server
                credentials = f"{choice}:{username}:{password}"
                ssock.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = ssock.recv(1024).decode("utf-8")
                print(f"Server: {response}")

                if "successful" in response.lower():
                    print("Sign-up successful! You can now log in.\n")
                    # Send the public key to the server
                    with open(public_filename, "rb") as public_file:
                        public_key_data = public_file.read()
                        ssock.send(public_key_data)  # Send the public key to the server

            elif choice == "2":
                print("\n--- Login ---")
                username = input("Enter your username: ")
                password = input("Enter your password: ")

                # Send action and credentials to the server
                credentials = f"{choice}:{username}:{password}"
                ssock.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = ssock.recv(1024).decode("utf-8")
                if "authentication successful" in response.lower():  # Check for success message from server
                    print(f"Login successful! Welcome back, {username}.\n")
                    authenticated = True  # Set flag to indicate successful login
                    break  # Exit loop after successful login
                else:
                    print(f"Login failed: {response}")

            elif choice == "3":
                print("Exiting the program.")
                ssock.close()
                break
        
        if authenticated:
            while True:
                print("1. Upload File")
                print("2. List Files")
                print("3. Download File")
                print("4. Exit")
                choicee = input("Choose an option: ")
                ssock.send(choicee.encode("utf-8") )

                if choicee == "1":
                    file_name = input("Enter file name: ")
                    file_address=input("Enter file path: ")
                    
                    #Open File and read data
                    file = open(file_address, "r")
                    data = file.read()

                    with open(file_address, "rb") as file:  # Open file in binary mode
                        binary_data = file.read()  # Read the file content as bytes
                    
                    # Calculate the hash value of the file
                    file_hash = hashlib.sha256(binary_data).hexdigest()
                    print(f"Calculated hash: {file_hash}")

                    # Load the private key from the stored file
                    with open(f"/Users/seifelmougy/Documents/file_server_storage_keys/{username}/{username}_private.pem", "rb") as key_file:
                        private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        )

                    # Generate a digital signature for the file data
                    signature = private_key.sign(
                        binary_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    file = f"{file_name}:{data}"

                    ssock.send(file.encode("utf-8") ) # Send file data and file name
                    ssock.send(signature)  # Send the signature
                    ssock.send(file_hash.encode("utf-8"))
                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")


                elif choicee == "2":
                    File_list = ssock.recv(1024).decode("utf-8")
                    print(f"The following files are available in your folder: {File_list}")

                elif choicee == "3":
                    # Load the private key from the stored file
                    with open(f"/Users/seifelmougy/Documents/file_server_storage_keys/{username}/{username}_private.pem", "rb") as key_file:
                        private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        )

                    desired_file_name = input("Enter file name: ")
                    ssock.send(desired_file_name.encode("utf-8") )
                    
                    # Receive the encrypted data from the server
                    downloaded_file_data= ssock.recv(1024)

                    
                    decrypted_data = private_key.decrypt(
                        downloaded_file_data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # Save the decrypted file locally
                    os.chdir(f"/Users/seifelmougy/Documents/file_server_storage_Downloads/{username}")
                    with open(desired_file_name, "wb") as file:
                        file.write(decrypted_data)
                    with open(desired_file_name, "rb") as file2:
                        decrypted_file_binary_data = file2.read()  # Read the file content as bytes

                    print(f"File '{desired_file_name}' downloaded and decrypted successfully.")   
                    decrypted_file_hash = hashlib.sha256(decrypted_file_binary_data).hexdigest()
                    file_hash_received = ssock.recv(1024).decode("utf-8")
                    if decrypted_file_hash == file_hash_received:
                        print("Hash match confirmed.")
                    else: 
                        print("Hash match Failed!")               

                elif choicee == "4":
                    print("Exiting the program.")
                    ssock.close()
                    break

if __name__ == "__main__":
    main()
