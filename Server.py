import socket
import mysql.connector
import bcrypt
import ssl
import os

def main():

    # MYSQL Database
    db = mysql.connector.connect(user='root',password='root1234',host='localhost', database='file_server')

    cursor = db.cursor()

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

        # File Transfer
        choicee = client_socket.recv(1024).decode("utf-8")


        if choicee == '1':
            file_data = client_socket.recv(1024).decode("utf-8")
            file_name, data = file_data.split(":")

            print("Filename received.")
            file = open(file_name, "w")
            client_socket.send("Filename received.".encode("utf-8"))


            print("File Data received")
            file.write(data)
            client_socket.send("File data received.".encode("utf-8"))

            file.close()

        if choicee == '2':

            List = str(os.listdir())
            client_socket.send(List.encode("utf-8"))


        if choicee == '3':
            client_socket.close()
            server_socket.close()


        client_socket.close()
        server_socket.close()




if __name__ == "__main__":
    main()