from http import server
from http.server import HTTPServer      #choose a port, serve until ctrl + c 
from http.server import BaseHTTPRequestHandler      #handle get requests


class requestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)     #status code 200
        self.send_header('content-type', 'text/html')       #specify the format
        self.end_headers()
        self.wfile.write("Response".encode())            #wfile ->writable file


PORT = 5555
server = HTTPServer(('', PORT), requestHandler)           #first argument -> hostname/ domain name. blank for localhost

print(f"Running on {PORT}")

server.serve_forever()

