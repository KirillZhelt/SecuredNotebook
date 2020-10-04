# Secured Notebook

Protocol of communication:
1. The client connects to the server.
2. The client sends RSA open key to the server.
3. The client asks server to generate session key.
4. The server generates session key and sends it to the client.

    Main communication loop

5. a) The client asks server to send the text from a file with the specified name.
6. a) The server encrypts the text and sends it to the client.
5. b) The client asks server to regenerate session key.
6. b) The server generates session key and sends it to the client.
