import http.server
import socketserver
import os
import ssl


PORT = 8000  # Feel free to use a different port


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()


os.chdir('/path/to/your/files')  # Replace with your directory path


handler_object = MyHttpRequestHandler


with socketserver.TCPServer(("", PORT), handler_object) as httpd:
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="server.pem", certfile="server.pem", server_side=True)

    print(f"Serving at port {PORT}")
    print("Server is running. Press Ctrl+C to stop the server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server stopped.")
    httpd.server_close()
    print("Server closed.")