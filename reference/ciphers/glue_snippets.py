# Non-cryptographic glue code that composite/system questions need on top of
# the actual ciphers -- key/IV normalization, timestamps, and tamper
# simulation. None of this is "a cipher" (it's ordinary Python), but it's
# copy-paste ready exactly like the algorithm files are, so it lives here
# instead of only in the notes under guide/

from datetime import datetime


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_bytes(text, length):
    """Turns any user-typed string into an exact-length key/IV by truncating
    or zero-padding, so AES never rejects a 'wrong size' key. Use length=16
    for AES-128 (or any cipher's IV), 24 for AES-192, 32 for AES-256."""
    raw = text.encode()[:length]
    return raw.ljust(length, b"\0")


def tamper_hex(ciphertext_hex):
    """Flips the last hex character to simulate corruption/tampering of a
    hex-string ciphertext -- what ciphers/aes.py, rsa.py, tripledes.py etc.
    all return. Use this for "show integrity check fails" requirements."""
    last = ciphertext_hex[-1]
    flipped = "0" if last != "0" else "1"

    return ciphertext_hex[:-1] + flipped


def tamper_bytes(data):
    """Flips the last byte to simulate corruption/tampering of raw bytes
    (e.g. file content encrypted with file_transfer.py-style bytes-native
    functions)."""
    tampered = bytearray(data)
    tampered[-1] ^= 0xFF

    return bytes(tampered)


if __name__ == "__main__":
    print("timestamp()          :", timestamp())
    print("normalize_bytes('hi', 16) :", normalize_bytes("hi", 16))
    print("tamper_hex('abcd')   :", tamper_hex("abcd"))
    print("tamper_bytes(b'hello'):", tamper_bytes(b"hello"))
