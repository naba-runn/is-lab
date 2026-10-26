# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q18 HashLab -- hashing and integrity                                (lab 5)
#  Implement the custom hash (start 5381, h = h*33 + c, 32-bit mask), hash 50
#  random strings with MD5, SHA-1, SHA-256 and the custom hash, time them,
#  look for collisions; then send data over a socket and verify the hash on
#  the server.
#
# Hand-written template (hash speed / collisions + socket integrity).
# Run:  python q18_hashlab.py                (speed + collision table)
#       python q18_hashlab.py server   then   python q18_hashlab.py client
#       python q18_hashlab.py test
# =============================================================================

import hashlib
import random
import socket
import string
import sys
import time


# ---------- from ciphers/hash_function.py (verbatim) ----------

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

    return format(hash_value, "08x")


# ---------- from ciphers/hashing.py (verbatim) ----------

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ==================== CHANGE: settings ====================

COUNT = 50                 # CHANGE: how many random strings
LENGTH = 20                # CHANGE: length of each string
HOST, PORT = "127.0.0.1", 5051
HASHES = [("MD5", md5_hash), ("SHA-1", sha1_hash), ("SHA-256", sha256_hash), ("custom (djb2)", custom_hash)]


# ---------- input / output helpers ----------

def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Please type something.")


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=24):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


# ---------- part 1: speed + collisions ----------

def hash_table(count=COUNT, length=LENGTH):
    data = ["".join(random.choice(string.ascii_letters + string.digits) for _ in range(length)) for _ in range(count)]
    section("hashing %d random strings of %d characters" % (count, length))
    print("  %-14s %12s %12s %s" % ("hash", "total ms", "digest len", "collisions"))
    results = {}
    for name, fn in HASHES:
        start = time.perf_counter()
        digests = [fn(s) for s in data]
        ms = (time.perf_counter() - start) * 1000
        collisions = len(digests) - len(set(digests))
        results[name] = collisions
        print("  %-14s %12.3f %12d %d" % (name, ms, len(digests[0]), collisions))
    show("example", data[0] + " -> " + sha256_hash(data[0]))
    return results


# ---------- part 2: integrity over a socket ----------

def server(max_connections=None, ready=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening on", HOST, PORT)
        if ready is not None:
            ready.set()
        handled = 0
        while max_connections is None or handled < max_connections:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(65536).decode()
                digest = sha256_hash(data)                 # CHANGE: custom_hash(data) if asked
                show("server received", data)
                show("server hash", digest)
                conn.sendall(digest.encode())
            handled += 1


def client(message, tamper=False):
    local = sha256_hash(message)
    sent = message[:-1] + "#" if tamper else message      # simulate corruption on the way
    with socket.create_connection((HOST, PORT)) as c:
        c.sendall(sent.encode())
        received = c.recv(4096).decode()
    show("client hash (original)", local)
    show("hash from server", received)
    ok = local == received
    print("  INTEGRITY " + ("PASSED" if ok else "FAILED -- data was altered"))
    return ok


def main():
    hash_table()


def self_test():
    import threading
    global PORT
    assert all(c == 0 for c in hash_table(50, 20).values())
    probe = socket.socket(); probe.bind((HOST, 0)); PORT = probe.getsockname()[1]; probe.close()
    ready = threading.Event()
    t = threading.Thread(target=server, args=(2, ready)); t.start(); ready.wait()
    assert client("Transfer 500 to account 12345") is True
    assert client("Transfer 500 to account 12345", tamper=True) is False
    t.join()
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        self_test()
    elif len(sys.argv) > 1 and sys.argv[1] == "server":
        server()
    elif len(sys.argv) > 1 and sys.argv[1] == "client":
        client(input("Message: "), tamper=input("Tamper on the way? (y/n): ").lower().startswith("y"))
    else:
        main()
