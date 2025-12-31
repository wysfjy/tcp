import socket
import threading

def handle_client(client_socket):
    request = client_socket.recv(1024).decode('utf-8')
    response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    response += "<html><body><h1>Test HTTP S1erver</h1><p>Hello from the test server!</p></body></html>"
    client_socket.send(response.encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 3399))
    server.listen(5)
    print("Test HTTP server running on http://0.0.0.0:3399")
    
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == '__main__':
    main()