import hashlib
import socket

HOST = "127.0.0.1"
PORT = 65433


def rsa_message_number(message, n):
    """What is actually signed: SHA-256 of the message as a number, reduced mod n."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % n


def rsa_sign(message, d, n):
    return str(pow(rsa_message_number(message, n), d, n))


def start_server(d, n, host=HOST, port=PORT):
    """Signs a document and sends both the document and its signature to
    whichever client connects, so the client can verify it independently."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[Server] Listening on {host}:{port}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            document = "Alice"
            signature = rsa_sign(document, d, n)
            print(f"[Server] Signing document: {document!r}")

            payload = f"{document}|{signature}"
            conn.sendall(payload.encode())
            print("[Server] Sent document + signature to client")


if __name__ == "__main__":
    # Same demo RSA keys used in rsa_signature.py
    n = int(
        "d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a"
        "68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55f"
        "dcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474ba"
        "bc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549", 16
    )
    d = int(
        "47b9cfde843176b88741d68cf096952e950813151058ce46f2b048791a26e507a"
        "1095793c12bae1e09d82213ad9326928cf7c2350acb19c98f19d32d577d666cd7"
        "bb8b2b5ba629d25ccf72a5ceb8a8da038906c84dcdb1fe677dffb2c029fd892631"
        "8eede1b58272af22bda5c5232be066839398e42f5352df58848adad11a1", 16
    )

    start_server(d, n)
