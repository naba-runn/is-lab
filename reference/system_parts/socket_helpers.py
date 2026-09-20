# TCP client/server on one machine, plus pack/unpack for sending several pieces
# (ciphertext + hash + signature) in one message.
#
# In an exam the server and client are usually two scripts: start the server
# FIRST (a second terminal, or a second PyCharm run configuration), then the
# client. Full two-script versions: problems/hash_server.py + hash_client.py
# and problems/signature_server.py + signature_client.py.
#
# The demo below runs both in one file using a thread, so it is self-testing.

import socket
import threading

HOST = "127.0.0.1"
PORT = 65432


def pack(*pieces):
    """pack(cipher_hex, hash_hex, signature) -> one string. "|" separates the
    pieces, which is safe for hex strings and integers."""
    return "|".join(str(piece) for piece in pieces)


def unpack(data):
    return data.split("|")


def serve_once(handler, host=HOST, port=PORT, ready=None):
    """Waits for ONE client, calls handler(received_text) and sends back the
    string it returns."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        if ready:
            ready.set()                     # tells the demo "I'm listening"

        conn, _ = server.accept()
        with conn:
            received = conn.recv(65536).decode()
            conn.sendall(handler(received).encode())


def send_and_receive(message, host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((host, port))
        client.sendall(message.encode())

        return client.recv(65536).decode()


if __name__ == "__main__":
    def handler(received):
        cipher_hex, hash_hex, signature = unpack(received)
        print("[server] got:", cipher_hex, hash_hex, int(signature))
        return "OK: " + hash_hex

    ready = threading.Event()
    server_thread = threading.Thread(target=serve_once, args=(handler,), kwargs={"ready": ready})
    server_thread.start()
    ready.wait()

    reply = send_and_receive(pack("ab12cd", "f00d", 123456789 ** 5))
    print("[client] reply:", reply)
    server_thread.join()
