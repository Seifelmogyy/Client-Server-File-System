import socket
import mysql.connector




def main():

    # MYSQL Database
    db = mysql.connector.connect(user='root',password='root1234',host='localhost', database='file_server')

    cursor = db.cursor()
  
    # Server Socket Initialization
    server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1',12345))
    server_socket.listen(5)
    print ("server waiting for connection")
    
    client_socket,addr=server_socket.accept()
    print ("client connected from", addr)



    filename = client_socket.recv(1024).decode("utf-8")
    print("Filename received.")
    file = open(filename, "w")
    client_socket.send("Filename received.".encode("utf-8"))


    data = client_socket.recv(1024).decode("utf-8")
    print("File Data received")
    file.write(data)
    client_socket.send("File data received.".encode("utf-8"))

    file.close()
    client_socket.close()
    server_socket.close()




if __name__ == "__main__":
    main()