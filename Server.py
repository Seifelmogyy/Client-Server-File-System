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

def register_user(username, password):
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Define the folder path for this user
    folder_path = f"/path/to/storage/{username}"

    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Create the user's folder
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        # Insert the user into the database
        insert_query = """
        INSERT INTO users (username, password_hash, folder_path)
        VALUES (%s, %s, %s)
        """
        cursor.execute(insert_query, (username, hashed_password.decode('utf-8'), folder_path))
        connection.commit()
        cursor.close()
        connection.close()
        
        print("User registered successfully!")
    except Exception as e:
        print("Error registering user:", e)

# Register a new user
register_user("newuser", "securepassword")



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
        if self.path == "/login":
            # Handle login
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            credentials = json.loads(post_data)

            username = credentials.get('username')
            password = credentials.get('password')

            authenticated, user_id = verify_credentials(username, password)

            if authenticated:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "user_id": user_id}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "failed"}).encode())

        elif self.path == "/signup":
            # Handle signup
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            new_user = json.loads(post_data)

            username = new_user.get('username')
            password = new_user.get('password')

            # Check if username and password are provided
            if not username or not password:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "failed", "message": "Username and password required"}).encode())
                return

            # Create a new user
            if register_user(username, password):
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            else:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "failed", "message": "Failed to create user"}).encode())

        elif self.path == "/upload":
            # Handle file upload
            user_id = int(self.headers.get('User-ID'))

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Save the uploaded file in the user-specific folder
            user_dir = f"files/{user_id}"
            if not os.path.exists(user_dir):
                os.makedirs(user_dir)

            filename = "uploaded_file"  # Placeholder name
            file_path = os.path.join(user_dir, filename)

            with open(file_path, 'wb') as output_file:
                output_file.write(post_data)

            # Record the file in the database
            connection = mysql.connector.connect(**db_config)
            cursor = connection.cursor()
            cursor.execute("INSERT INTO user_files (user_id, filename) VALUES (%s, %s)", (user_id, filename))
            connection.commit()
            cursor.close()
            connection.close()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"File uploaded successfully!")

        elif self.path == "/download":
            # Handle file download
            user_id = int(self.headers.get('User-ID'))
            filename = self.headers.get('Filename')

            user_dir = f"files/{user_id}"
            file_path = os.path.join(user_dir, filename)

            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.end_headers()
                with open(file_path, 'rb') as file:
                    self.wfile.write(file.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")


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