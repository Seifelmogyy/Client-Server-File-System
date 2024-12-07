import socket
import mysql.connector
import bcrypt
import ssl
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib

def main():

    # MYSQL Database
    db = mysql.connector.connect(user='root',password='root1234',host='localhost', database='file_server')

    cursor = db.cursor()

    def get_public_key_from_db(username):
        """
        Retrieve the public key for a user from the MySQL database.
        """
        # Query for the public key
        query = "SELECT public_key FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        if result:
            public_key_pem = result[0]  # Public key in PEM format
            # Deserialize the public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            return public_key
        else:
            raise ValueError("Public key not found for user.")

    # Authenticate and Register Functions
    def authenticate_user(username, password):

        os.chdir(f"/Users/seifelmougy/Documents/file_server_storage/{username}")

        """Authenticate user by comparing entered password with stored hash."""
        query = "SELECT password_hash FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
    
        if result:
            stored_password = result[0].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                return True
        return False
    
    def register_user(username, password):

        nested_directory = f"/Users/seifelmougy/Documents/file_server_storage/{username}"

        try:
            os.makedirs(nested_directory)
            print(f"Nested directories '{nested_directory}' created successfully.")
        except FileExistsError:
            print(f"One or more directories in '{nested_directory}' already exist.")
            
        download_nested_directory = f"/Users/seifelmougy/Documents/file_server_storage_Downloads/{username}"

        try:
            os.makedirs(download_nested_directory)
            print(f"Nested directories '{download_nested_directory}' created successfully.")
        except FileExistsError:
            print(f"One or more directories in '{download_nested_directory}' already exist.")

        """Register a new user with a hashed password."""
        query = "SELECT username FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        if cursor.fetchone():
            return "User already exists"

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        query = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password.decode('utf-8')))
        db.commit()
        return "Registration successful"
    
    def save_public_key(username, public_key_data):
        try:
            # Convert the public key to string (PEM format)
            public_key_str = public_key_data.decode("utf-8")

            # Insert the public key into the database
            query = "UPDATE users SET public_key = %s WHERE username = %s"
            cursor.execute(query, (public_key_str, username))
            db.commit()
            print(f"Public key for {username} saved to the database.")
        except Exception as e:
            print(f"Error saving public key: {e}")

    def store_file_in_database(username, file_name, file_hash):
        """
        Store the file name, username, and file hash in the database.
        """
        query = "INSERT INTO files (username, file_name, file_hash) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, file_name, file_hash))
        db.commit()
        print(f"File '{file_name}' with hash '{file_hash}' stored in database for user '{username}'.")

    def fetch_file_hash_from_db(username, file_name):
        query = "SELECT file_hash FROM files WHERE username = %s AND file_name = %s"
        cursor.execute(query, (username, file_name,))
        result = cursor.fetchone()
        file_hash = result[0]
        return file_hash
    
  
    # Server Socket Initialization and SSL
    context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("mycert.crt","mykey.key")
    server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(server_socket,server_side=True) as sssock:
        sssock.bind(('127.0.0.1',12345))
        sssock.listen(5)
        print ("server waiting for connection")

        client_socket,addr=sssock.accept()
        print ("client connected from", addr)

        # Receive action and credentials from the client
        acc_data = client_socket.recv(1024).decode("utf-8")
        choice, username, password = acc_data.split(":")

        if choice == '2':
            if authenticate_user(username, password):
                client_socket.send("Authentication successful".encode("utf-8"))

            else:
                client_socket.send("Authentication failed".encode("utf-8"))
        elif choice == '1':
            response = register_user(username, password)
            client_socket.send(response.encode("utf-8"))
            public_key_data = client_socket.recv(2048)  # Adjust size as needed
            public_key = serialization.load_pem_public_key(public_key_data)
            save_public_key(username, public_key_data)

        # File Transfer
        choicee = client_socket.recv(1024).decode("utf-8")
    while True:
        if choicee == '1':
            #Loading the public key 
            public_key = get_public_key_from_db(username)

            #Receiving file name and content from client
            file_data = client_socket.recv(1024).decode("utf-8")
            file_name, data = file_data.split(":")
                # Path to the user's directory (assuming the directory structure is based on the username)
            user_directory = f"/Users/seifelmougy/Documents/file_server_storage/{username}"
            
            # Check if the file already exists in the user's directory
            if os.path.exists(os.path.join(user_directory, file_name)):
                client_socket.send("Error: File with this name already exists.".encode("utf-8"))
                print(f"File upload rejected: {file_name} already exists for user {username}.")
            else:
                #Convert the file data (string) to bytes for encryption
                data_bytes = data.encode("utf-8")

                #Receive File Signature
                signature = client_socket.recv(1024)

                # Verify the digital signature using the client's public key
                try:
                    public_key.verify(
                        signature,
                        data_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    client_socket.send("Signature verification successful.".encode("utf-8"))
                    print("Signature verification Successful.")

                except Exception as e:
                    # If verification fails, send an error message to the client
                    client_socket.send(f"Signature verification failed: {str(e)}".encode("utf-8"))
                    print("Signature verification failed.")

                file_hash_received = client_socket.recv(1024).decode("utf-8")

                # Store the file name, username, and hash in the database
                store_file_in_database(username, file_name, file_hash_received)

                server_file_hash = hashlib.sha256(data_bytes).hexdigest()
                print(f"Calculated hash: {server_file_hash}")
                if server_file_hash == file_hash_received:
                    client_socket.send("Hash match confirmed. Proceeding with file encryption.".encode("utf-8"))
                    print("Hash match confirmed. Proceeding with file encryption.")

                #Encrypt file data
                encrypted_data = public_key.encrypt(
                data_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
                print("Filename received.")

                file = open(file_name, "wb")
                client_socket.send("Filename received.".encode("utf-8"))


                print("File Data received")
                file.write(encrypted_data)
                client_socket.send("File data received.".encode("utf-8"))

                file.close()

        elif choicee == '2':

            List = str(os.listdir())
            client_socket.send(List.encode("utf-8"))
        
        elif choicee == '3':
           desired_file_name = client_socket.recv(1024).decode("utf-8")
           file_address = f"/Users/seifelmougy/Documents/file_server_storage/{username}/{desired_file_name}"
           file_to_send = open(file_address, "rb")
           data_to_send = file_to_send.read()
           # Send File hash
           file_hash_to_send = fetch_file_hash_from_db(username, desired_file_name)
           print(f"File Hash to send {file_hash_to_send}")

           client_socket.send(data_to_send)
           client_socket.send(file_hash_to_send.encode("utf-8"))


        elif choicee == '4':
            # Close the client and server sockets when choice is '4'
            client_socket.send("Closing connection.".encode("utf-8"))
            print("Connection closing...")
            client_socket.close()
            break


        client_socket.close()
        server_socket.close()




if __name__ == "__main__":
    main()