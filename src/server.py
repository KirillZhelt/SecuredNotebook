import socket
import threading
import os
import datetime

import gm
import idea

from protocol import *
from transport import *

HOST = ''
PORT = 11555


FILES_DIRECTORY_PATH = 'storage/'
SESSION_KEY_EXPIRY_DELTA = datetime.timedelta(seconds=10)
PASSWORD_HASH = b'\x92\x9c\xad\x87G4\xfa%\xcc\xf1.,\xeb\xce\x00\xce\xf6\x99g\x15\x9f\x81M\xba0\x84\x89W\xa0\x81bA\x9cI\xecN\xd0\xeac\xf3\xdf\x98\xe6U\xb6\xb7\xa6\xf3:\xdf\x1cr\xfb\xef\xb06\xb3\xee\x87r`\xb2\xa3&\xb9\xdc\x19l\x1chY\x84\xe3\xdd\xc5\xe8;\xc3ZRr\x860a\xff\xd7O\\\x02z\x88\xdb%z\xc1\x15@\x95\x82u\xcc\xefm\x90T\x07%\xa6\xeb`\xa0\xb6\xd69\xdcEp6\xfc$\xd2\x0e\x0b\x84j\xa3/X'


def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def get_file_names(files_dir_path):
    return [entry.name for entry in os.scandir(files_dir_path) if entry.is_file()] 


def handle_client(conn, addr):
    with conn:
        print('Connected by', addr)

        hello_request = Message.from_bytes(recv_msg(conn))
        if not isinstance(hello_request, ClientHelloRequest):
            raise IllegalMessageException()
        else:
            send_msg(conn, Message.to_bytes(ServerOkResponse()))

        authenticated = False
        while not authenticated:
            password_request = Message.from_bytes(recv_msg(conn))
            if not isinstance(password_request, SendPasswordRequest):
                raise IllegalMessageException()
            elif password_request.password == PASSWORD_HASH:
                authenticated = True
                send_msg(conn, Message.to_bytes(ServerOkResponse()))
            else:
                send_msg(conn, Message.to_bytes(WrongPasswordResponse()))

        gm_request = Message.from_bytes(recv_msg(conn))
        if not isinstance(gm_request, SendOpenKeyRequest):
            raise IllegalMessageException()
        else:
            open_gm_key = gm_request.open_key
            send_msg(conn, Message.to_bytes(ServerOkResponse()))

        session_key = None
        session_key_generation_time = None
        while True:
            request = Message.from_bytes(recv_msg(conn))
            if isinstance(request, GetSessionKeyRequest):
                session_key = idea.generate_key()
                session_key_generation_time = datetime.datetime.now()
                encrypted_session_key = gm.encrypt(session_key, open_gm_key)
                send_msg(conn, Message.to_bytes(GetSessionKeyResponse(encrypted_session_key)))
            elif isinstance(request, GetFileTextRequest):
                if not session_key:
                    raise IllegalMessageException('Client should request session key before file text')

                if datetime.datetime.now() - session_key_generation_time > SESSION_KEY_EXPIRY_DELTA:
                    send_msg(conn, Message.to_bytes(SessionKeyExpiredResponse()))
                else:    
                    file_name = request.file_name
                    file_text = read_file(FILES_DIRECTORY_PATH + file_name)
                    encrypted_file_text, initialization_list = idea.encrypt(file_text, session_key)
                    send_msg(conn, Message.to_bytes(GetFileTextResponse(encrypted_file_text, initialization_list)))
            elif isinstance(request, GetFileNamesRequest):
                send_msg(conn, Message.to_bytes(GetFileNamesResponse(get_file_names(FILES_DIRECTORY_PATH))))
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
