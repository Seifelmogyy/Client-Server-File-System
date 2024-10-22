import http.server
import socketserver
import os
import ssl
import cgi



PORT = 8000  # Feel free to use a different port


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        return super().do_GET()

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