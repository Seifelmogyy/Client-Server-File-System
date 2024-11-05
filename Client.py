import socket

def sign_up():
    print("\n--- Sign Up ---")
    username = input("Enter a new username: ")
    password = input("Enter a new password: ")
    credentials = f"{username}:{password}"
    
    print("Sign-up successful! You can now log in.\n")

def login():
    print("\n--- Login ---")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    credentials = f"{username}:{password}"
    print("Login successful! Welcome back, {}.\n".format(username))

 
def main():
        client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1',12345))

        #Authentication
        while True:
            print("1. Sign Up")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ")
            if choice == "1":
                sign_up()
                client_socket.send(file_name.encode("utf-8") )
            elif choice == "2":
                login()
            elif choice == "3":
                print("Exiting the program.")
                break

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
