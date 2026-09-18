import socket
import sys

HOST = "127.0.0.1"
PORT = 65432


def custom_hash(data):
    """djb2-style hash: start at 5381, multiply by 33 and add each
    character's ASCII value, with an XOR-shift mixing step, masked to
    32 bits. See ciphers/hash_function.py for the standalone version."""
    hash_value = 5381

    for char in data:
        hash_value = (hash_value * 33) + ord(char)
        hash_value ^= (hash_value >> 13)
        hash_value &= 0xFFFFFFFF

    return hash_value


def send_message(message, tamper=False, host=HOST, port=PORT):
    """local_hash is computed on the original message before anything is
    sent. Set tamper=True to simulate the message being corrupted in transit
    (after that local hash was taken) -- the server will then hash different
    bytes than the client did, and the integrity check below should fail."""
    local_hash = custom_hash(message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        wire_message = message
        if tamper:
            wire_message = message[:-1] + ("X" if message[-1] != "X" else "Y")
            print(f"[Client] (simulating tampering) sending {wire_message!r} instead of {message!r}")

        client_socket.sendall(wire_message.encode())

        received_hash = int(client_socket.recv(4096).decode())

    print(f"[Client] Local hash of original message : {local_hash:#010x}")
    print(f"[Client] Hash received from server       : {received_hash:#010x}")

    if local_hash == received_hash:
        print("[Client] Integrity check PASSED -- data was not altered")
    else:
        print("[Client] Integrity check FAILED -- data was corrupted or tampered with")


if __name__ == "__main__":
    tamper = "--tamper" in sys.argv
    send_message("Transfer $500 to account 12345", tamper=tamper)
