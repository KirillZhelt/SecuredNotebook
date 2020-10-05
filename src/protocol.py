HELLO_MESSAGE_TYPE = 'HELLO'
SEND_RSA_OPEN_KEY_MESSAGE_TYPE = 'SEND_RSA_OPEN_KEY'
REQUEST_SESSION_KEY_MESSAGE_TYPE = 'REQUEST_SESSION_KEY'
RESPONSE_SESSION_KEY_MESSAGE_TYPE = 'RESPONSE_SESSION_KEY'
REQUEST_FILE_NAMES_MESSAGE_TYPE = 'REQUEST_FILE_NAMES'
RESPONSE_FILE_NAMES_MESSAGE_TYPE = 'RESPONSE_FILE_NAMES'
REQUEST_FILE_TEXT_MESSAGE_TYPE = 'REQUEST_FILE_TEXT'
RESPONSE_FILE_TEXT_MESSAGE_TYPE = 'RESPONSE_FILE_TEXT'
SERVER_OK_MESSAGE_TYPE = 'SERVER_OK'

MESSAGE_TYPE_KEY = 'message_type'


class WrongFormatException(Exception): pass


class BaseMessage:

    def to_dict(self):
        return { MESSAGE_TYPE_KEY: self.MESSAGE_TYPE }

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == cls.MESSAGE_TYPE:
            return cls()
        
        raise WrongFormatException()

class ClientHelloRequest(BaseMessage): 
    MESSAGE_TYPE = HELLO_MESSAGE_TYPE


class SendRSAOpenKeyRequest(BaseMessage):
    MESSAGE_TYPE = SEND_RSA_OPEN_KEY_MESSAGE_TYPE

    _OPEN_KEY_KEY = 'open_key'

    def __init__(self, open_key):
        self._open_key = open_key

    @property
    def open_key(self):
        return self._open_key

    def to_dict(self):
        message_dict = super().to_dict()
        message_dict[SendRSAOpenKeyRequest._OPEN_KEY_KEY] = self._open_key
        return message_dict

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == SendRSAOpenKeyRequest.MESSAGE_TYPE:
            if SendRSAOpenKeyRequest._OPEN_KEY_KEY not in message_dict:
                raise WrongFormatException()

            return cls(message_dict[SendRSAOpenKeyRequest._OPEN_KEY_KEY])

        raise WrongFormatException()


class GetSessionKeyRequest(BaseMessage):
    MESSAGE_TYPE = REQUEST_SESSION_KEY_MESSAGE_TYPE

class GetSessionKeyResponse(BaseMessage):
    MESSAGE_TYPE = RESPONSE_SESSION_KEY_MESSAGE_TYPE
    _ENCRYPTED_SESSION_KEY_KEY = 'encrypted_session_key'

    def __init__(self, encrypted_session_key):
        self._encrypted_session_key = encrypted_session_key

    @property
    def encrypted_session_key(self):
        return self._encrypted_session_key

    def to_dict(self):
        message_dict = super().to_dict()
        message_dict[GetSessionKeyResponse._ENCRYPTED_SESSION_KEY_KEY] = self._encrypted_session_key
        return message_dict

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == GetSessionKeyResponse.MESSAGE_TYPE:
            if GetSessionKeyResponse._ENCRYPTED_SESSION_KEY_KEY not in message_dict:
                raise WrongFormatException()

            return cls(message_dict[GetSessionKeyResponse._ENCRYPTED_SESSION_KEY_KEY])

        raise WrongFormatException()


class GetFileNamesRequest(BaseMessage):
    MESSAGE_TYPE = REQUEST_FILE_NAMES_MESSAGE_TYPE


class GetFileNamesResponse(BaseMessage):
    MESSAGE_TYPE = RESPONSE_FILE_NAMES_MESSAGE_TYPE
    _FILE_NAMES_KEY = 'file_names' 

    def __init__(self, file_names):
        self._file_names = file_names

    @property
    def file_names(self):
        return self._file_names

    def to_dict(self):
        message_dict = super().to_dict()
        message_dict[GetFileNamesResponse._FILE_NAMES_KEY] = self._file_names
        return message_dict

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == GetFileNamesResponse.MESSAGE_TYPE:
            if GetFileNamesResponse._FILE_NAMES_KEY not in message_dict:
                raise WrongFormatException()

            return cls(message_dict[GetFileNamesResponse._FILE_NAMES_KEY])

        raise WrongFormatException()

class GetFileTextRequest(BaseMessage):
    MESSAGE_TYPE = REQUEST_FILE_TEXT_MESSAGE_TYPE

    _FILE_NAME_KEY = 'file_name'

    def __init__(self, file_name):
        self._file_name = file_name

    @property
    def file_name(self):
        return self._file_name

    def to_dict(self):
        message_dict = super().to_dict()
        message_dict[GetFileTextRequest._FILE_NAME_KEY] = self._file_name
        return message_dict

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == GetFileTextRequest.MESSAGE_TYPE:
            if GetFileTextRequest._FILE_NAME_KEY not in message_dict:
                raise WrongFormatException()

            return cls(message_dict[GetFileTextRequest._FILE_NAME_KEY])

        raise WrongFormatException()


class GetFileTextResponse(BaseMessage):
    MESSAGE_TYPE = RESPONSE_FILE_TEXT_MESSAGE_TYPE

    _ENCRYPTED_TEXT_KEY = 'encrypted_text'
    _INITIALIZATION_LIST_KEY = 'initialization_list'

    def __init__(self, encrypted_text, initialization_list):
        self._encrypted_text = encrypted_text
        self._initialization_list = initialization_list

    @property
    def encrypted_text(self):
        return self._encrypted_text

    @property
    def initialization_list(self):
        return self._initialization_list

    def to_dict(self):
        message_dict = super().to_dict()
        message_dict[GetFileTextResponse._ENCRYPTED_TEXT_KEY] = self._encrypted_text
        message_dict[GetFileTextResponse._INITIALIZATION_LIST_KEY] = self._initialization_list
        return message_dict

    @classmethod
    def from_dict(cls, message_dict):
        if message_dict[MESSAGE_TYPE_KEY] == GetFileTextResponse.MESSAGE_TYPE:
            if GetFileTextResponse._ENCRYPTED_TEXT_KEY not in message_dict:
                raise WrongFormatException()

            if GetFileTextResponse._INITIALIZATION_LIST_KEY not in message_dict:
                raise WrongFormatException()

            return cls(message_dict[GetFileTextResponse._ENCRYPTED_TEXT_KEY], message_dict[GetFileTextResponse._INITIALIZATION_LIST_KEY])

        raise WrongFormatException()


class ServerOkResponse(BaseMessage):
    MESSAGE_TYPE = SERVER_OK_MESSAGE_TYPE


class Message:

    @staticmethod
    def from_bytes(bytes):
        message_dict = eval(bytes.decode())
        message_type = message_dict[MESSAGE_TYPE_KEY]

        if message_type == HELLO_MESSAGE_TYPE:
            return ClientHelloRequest.from_dict(message_dict)
        elif message_type == SEND_RSA_OPEN_KEY_MESSAGE_TYPE:
            return SendRSAOpenKeyRequest.from_dict(message_dict)
        elif message_type == REQUEST_SESSION_KEY_MESSAGE_TYPE:
            return GetSessionKeyRequest.from_dict(message_dict)
        elif message_type == RESPONSE_SESSION_KEY_MESSAGE_TYPE:
            return GetSessionKeyResponse.from_dict(message_dict)
        elif message_type == REQUEST_FILE_TEXT_MESSAGE_TYPE:
            return GetFileTextRequest.from_dict(message_dict)
        elif message_type == RESPONSE_FILE_TEXT_MESSAGE_TYPE:
            return GetFileTextResponse.from_dict(message_dict)
        elif message_type == SERVER_OK_MESSAGE_TYPE:
            return ServerOkResponse.from_dict(message_dict)
        elif message_type == REQUEST_FILE_NAMES_MESSAGE_TYPE:
            return GetFileNamesRequest.from_dict(message_dict)
        elif message_type == RESPONSE_FILE_NAMES_MESSAGE_TYPE:
            return GetFileNamesResponse.from_dict(message_dict)

        raise WrongFormatException()

    @staticmethod
    def to_bytes(message):
        return repr(message.to_dict()).encode()


class IllegalMessageException(Exception): pass
