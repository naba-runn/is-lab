import socket

HOST = "127.0.0.1"
PORT = 65432


def custom_hash(data):
    """djb2-style hash: start at 5381, and for each character multiply the
    running hash by 33 and add the character's ASCII value. An XOR-shift step
    mixes the bits further, and the result is masked back to 32 bits after
    every character so it never grows unbounded."""
    hash_value = 5381

    for char in data:
        hash_value = (hash_value * 33) + ord(char)
        hash_value ^= (hash_value >> 13)      # bitwise mixing
        hash_value &= 0xFFFFFFFF              # keep to 32 bits

    return format(hash_value, "08x")      # hex string, like every hash in hashing.py


def start_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[Server] Listening on {host}:{port}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"[Server] Connected by {addr}")

            data = conn.recv(4096)
            message = data.decode()
            print(f"[Server] Received: {message!r}")

            digest = custom_hash(message)
            print(f"[Server] Computed hash: {digest}")

            conn.sendall(digest.encode())
            print("[Server] Hash sent back to client")


if __name__ == "__main__":
    start_server()
