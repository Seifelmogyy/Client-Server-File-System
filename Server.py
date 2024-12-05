import socket
import mysql.connector
import bcrypt
import ssl
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
            print(public_key_data)
            print("Public key received and loaded.")
            save_public_key(username, public_key_data)

        # File Transfer
        choicee = client_socket.recv(1024).decode("utf-8")


        if choicee == '1':
            public_key = get_public_key_from_db(username)
            file_data = client_socket.recv(1024).decode("utf-8")
            file_name, data = file_data.split(":")

            # Convert the file data (string) to bytes for encryption
            data_bytes = data.encode("utf-8")

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

        if choicee == '2':

            List = str(os.listdir())
            client_socket.send(List.encode("utf-8"))
        
        if choicee == '3':
           desired_file_name = client_socket.recv(1024).decode("utf-8")
           file_address = f"/Users/seifelmougy/Documents/file_server_storage/{username}/{desired_file_name}"
           file_to_send = open(file_address, "rb")
           data_to_send = file_to_send.read()
           client_socket.send(data_to_send)


        if choicee == '4':
            client_socket.close()
            server_socket.close()


        client_socket.close()
        server_socket.close()




if __name__ == "__main__":
    main()