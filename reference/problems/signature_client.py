import hashlib
import socket

HOST = "127.0.0.1"
PORT = 65433


def rsa_message_number(message, n):
    """What is actually signed: SHA-256 of the message as a number, reduced mod n."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % n


def rsa_verify(message, signature, e, n):
    return pow(int(signature), e, n) == rsa_message_number(message, n)


def receive_and_verify(e, n, host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        payload = client_socket.recv(4096).decode()
        document, signature = payload.split("|")      # signature stays a string -- verify accepts it

    print(f"[Client] Received document : {document!r}")
    print(f"[Client] Received signature: {signature[:40]}...")

    if rsa_verify(document, signature, e, n):
        print("[Client] Signature is VALID -- document is authentic")
    else:
        print("[Client] Signature is INVALID -- document may be forged/corrupted")


if __name__ == "__main__":
    n = int(
        "d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a"
        "68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55f"
        "dcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474ba"
        "bc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549", 16
    )
    e = 0x10001

    receive_and_verify(e, n)
