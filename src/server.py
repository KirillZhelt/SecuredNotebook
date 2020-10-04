import socket
import threading

import rsa
import idea

from protocol import *
from transport import *

HOST = ''
PORT = 11555


FILES_DIRECTORY_PATH = 'storage/'


def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)

        hello_request = Message.from_bytes(recv_msg(conn))
        if not isinstance(hello_request, ClientHelloRequest):
            raise IllegalMessageException()
        else:
            send_msg(conn, Message.to_bytes(ServerOkResponse()))

        rsa_request = Message.from_bytes(recv_msg(conn))
        if not isinstance(rsa_request, SendRSAOpenKeyRequest):
            raise IllegalMessageException()
        else:
            open_rsa_key = rsa_request.open_key
            send_msg(conn, Message.to_bytes(ServerOkResponse()))

        session_key = None
        while True:
            request = Message.from_bytes(recv_msg(conn))
            if isinstance(request, GetSessionKeyRequest):
                session_key = idea.generate_key()
                encrypted_session_key = rsa.encrypt(session_key, open_rsa_key)
                send_msg(conn, Message.to_bytes(GetSessionKeyResponse(encrypted_session_key)))
            elif isinstance(request, GetFileTextRequest):
                if not session_key:
                    raise IllegalMessageException('Client should request session key before file text')

                file_name = request.file_name
                file_text = read_file(FILES_DIRECTORY_PATH + file_name)
                encrypted_file_text, initialization_list = idea.encrypt(file_text, session_key)
                send_msg(conn, Message.to_bytes(GetFileTextResponse(encrypted_file_text, initialization_list)))
            else:
                raise IllegalMessageException()


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()

            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()


if __name__ == '__main__':
    run_server()
