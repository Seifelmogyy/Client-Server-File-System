import socket

#Client Socket Server
client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1',12345))

 
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

                # Send action and credentials to the server
                credentials = f"{choice}:{username}:{password}"
                client_socket.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = client_socket.recv(1024).decode("utf-8")
                print(f"Server: {response}")

            elif choice == "2":
                print("\n--- Login ---")
                username = input("Enter your username: ")
                password = input("Enter your password: ")

                # Send action and credentials to the server
                credentials = f"{choice}:{username}:{password}"
                client_socket.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = client_socket.recv(1024).decode("utf-8")
                if "authentication successful" in response.lower():  # Check for success message from server
                    print(f"Login successful! Welcome back, {username}.\n")
                    authenticated = True  # Set flag to indicate successful login
                    break  # Exit loop after successful login
                else:
                    print(f"Login failed: {response}")

            elif choice == "3":
                print("Exiting the program.")
                client_socket.close()
                break
        
        if authenticated:
            file_name = input("Enter file name")
            file_address=input("enter file path: ")
            file = open(file_address, "r")

            data = file.read()

            client_socket.send(file_name.encode("utf-8") )
            msg = client_socket.recv(1024).decode("utf-8")
            print(f"Server: {msg}")

            client_socket.send(data.encode("utf-8"))
            msg = client_socket.recv(1024).decode("utf-8")
            print(f"Server: {msg}")

            file.close()
            client_socket.close()

if __name__ == "__main__":
    main()
