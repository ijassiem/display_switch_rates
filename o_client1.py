# echo_client.py

import socket, sys

HOST, PORT = "localhost", 9999
data = " ".join(sys.argv[1:])
print 'data = %s' %data

# create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # connect to server
    sock.connect((HOST, PORT))

    # send data
    sock.sendall(bytes(data + "\n"))

    # receive data back from the server
    received = str(sock.recv(1024))
finally:
    # shut down
    sock.close()

print("Sent:     {}".format(data))
print("Received: {}".format(received))