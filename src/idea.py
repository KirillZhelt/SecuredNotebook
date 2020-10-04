def generate_key():
    return 'idea_session_key'


def encrypt(text, key):
    return text, [1, 0, 1]


def decrypt(text, key, initialization_list):
    return text
