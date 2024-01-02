#!/usr/bin/env python3
import socket
import sys

CS_MESSAGE_PORT = 5000

def SendMessageToServer(args):
    TS_IP = args[1] # Grab the TS IP sent by Aggressor, as this is where the GraphStrike
    print(TS_IP)

    client_socket = socket.socket()  # get instance
    client_socket.connect((TS_IP, CS_MESSAGE_PORT))  # connect to the server

    delimiter = ":"
    message = delimiter.join(args[2:])

    client_socket.send(message.encode())  # send message

    # Print reply from main server instance. This will be picked up by the TS and acted on in the .cna script.
    data = client_socket.recv(1024).decode()  # receive response
    print(data)

    client_socket.close()  # close the connection

if __name__ == '__main__':
        SendMessageToServer(sys.argv)