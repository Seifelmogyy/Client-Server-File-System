import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

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
                password = input("Enter a new password: ")    
                print("Sign-up successful! You can now log in.\n")

                # Generate and save RSA keys for the user
                public_filename = generate_rsa_keys(username)

                # Send action and credentials to the server
                credentials = f"{choice}:{username}:{password}"
                ssock.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = ssock.recv(1024).decode("utf-8")
                print(f"Server: {response}")

                if "successful" in response.lower():
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
                print("3. Exit")
                choicee = input("Choose an option: ")
                ssock.send(choicee.encode("utf-8") )

                if choicee == "1":
                    file_name = input("Enter file name: ")
                    file_address=input("enter file path: ")
                    file = open(file_address, "r")

                    data = file.read()

                    file = f"{file_name}:{data}"

                    ssock.send(file.encode("utf-8") )
                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    #file.close()
                    #ssock.close()

                elif choicee == "2":
                    File_list = ssock.recv(1024).decode("utf-8")
                    print(f"The following files are available in your folder: {File_list}")



                elif choicee == "3":
                    print("Exiting the program.")
                    ssock.close()
                    break

if __name__ == "__main__":
    main()
