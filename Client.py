import socket
import ssl

#Client Socket Server
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("mycert.crt")
client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ssock = context.wrap_socket(client_socket) 
ssock.connect(('127.0.0.1',12345))

 
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
                ssock.send(credentials.encode("utf-8"))

                # Receive and print response from server
                response = ssock.recv(1024).decode("utf-8")
                print(f"Server: {response}")

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
                if choicee == "1":
                    file_name = input("Enter file name: ")
                    file_address=input("enter file path: ")
                    file = open(file_address, "r")

                    data = file.read()

                    file = f"{choicee}:{file_name}:{data}"

                    ssock.send(file.encode("utf-8") )
                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    msg = ssock.recv(1024).decode("utf-8")
                    print(f"Server: {msg}")

                    #file.close()
                    #ssock.close()
                elif choicee == "3":
                    print("Exiting the program.")
                    ssock.close()
                    break

if __name__ == "__main__":
    main()
