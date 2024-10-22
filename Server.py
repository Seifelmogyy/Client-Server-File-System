import http.server
import socketserver
import os
import ssl
import cgi
import _mysql_connector
import bcrypt
import json


PORT = 8000  # Feel free to use a different port

db_config = {
    'user': 'root',
    'password': 'root1234',
    'host': 'localhost',
    'database': 'file_server'
}

def verify_credentials(username, password):
    """Check if the username and password match a record in the database."""
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Query to retrieve password hash for the given username
        query = "SELECT id, password_hash FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        cursor.close()
        connection.close()

        if result is None:
            return False, None

        user_id, stored_password_hash = result

        # Check if the password matches the hash
        if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            return True, user_id
        return False, None

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False, None


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/list_files":
            # Handle listing files for a user
            user_id = int(self.headers.get('User-ID'))

            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            query = "SELECT filename FROM user_files WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            cursor.close()
            connection.close()

            # Extract file names
            file_list = [row[0] for row in result]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(file_list).encode())
        else:
            super().do_GET()  # Handle other GET requests as needed

    def do_POST(self):
        # Parse the form data posted
        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type'))
        if ctype == 'multipart/form-data':
            pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
            fields = cgi.parse_multipart(self.rfile, pdict)
            file_data = fields.get('file')  # The file field in the form
            file_name = fields.get('filename')[0]  # Extract filename

            if file_data and file_name:
                file_name = file_name.decode("utf-8")  # Ensure the filename is a string
                with open(file_name, 'wb') as output_file:
                    output_file.write(file_data[0])  # Write the file to the server

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"File uploaded successfully!")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Failed to upload the file.")

        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Only multipart form data is supported.")
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


os.chdir('/Users/seifelmougy/Documents/Year 4/Semester 1/Practical cryptograp/File Server')  # Replace with your directory path


handler_object = MyHttpRequestHandler


with socketserver.TCPServer(("", PORT), handler_object) as httpd:
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/server.pem", certfile="/Users/seifelmougy/Documents/GitHub/Client-Server-File-System/server.pem", server_side=True)

    print(f"Serving at port {PORT}")
    print("Server is running. Press Ctrl+C to stop the server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server stopped.")
    httpd.server_close()
    print("Server closed.")