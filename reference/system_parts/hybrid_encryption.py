# Hybrid encryption: AES encrypts the data, RSA encrypts only the short AES key.
#
# Use it whenever the data is longer than RSA can take directly (RSA-2048 with
# OAEP holds about 190 bytes) -- a file, a long record, a whole document.

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# ---- from ciphers/aes.py (verbatim) ----

def aes_encrypt(key, plaintext, iv=None):
    key_bytes = key.encode() if isinstance(key, str) else key
    iv = iv or get_random_bytes(AES.block_size)

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes_decrypt(key, ciphertext):
    key_bytes = key.encode() if isinstance(key, str) else key

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


# ---- from ciphers/rsa.py (verbatim) ----

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    numbers = private_key.private_numbers()

    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d

    return private_key, public_key, n, e, d


def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()


def rsa_decrypt(private_key, ciphertext):
    decrypted = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode()


# ---------- the hybrid part ----------

def random_aes_key():
    """16 random hex characters = a 16-byte AES-128 key, as text."""
    return get_random_bytes(8).hex()


def hybrid_encrypt(public_key, plaintext):
    """Returns (encrypted_data, encrypted_key). Store/send both."""
    aes_key = random_aes_key()

    return aes_encrypt(aes_key, plaintext), rsa_encrypt(public_key, aes_key)


def hybrid_decrypt(private_key, encrypted_data, encrypted_key):
    aes_key = rsa_decrypt(private_key, encrypted_key)

    return aes_decrypt(aes_key, encrypted_data)


if __name__ == "__main__":
    private_key, public_key, n, e, d = rsa_generate_keys()

    long_text = "Patient record line. " * 200          # ~4000 bytes: too big for RSA alone
    try:
        rsa_encrypt(public_key, long_text)
    except ValueError as error:
        print("RSA alone fails on long data:", error)

    encrypted_data, encrypted_key = hybrid_encrypt(public_key, long_text)
    print("encrypted AES key (hex):", encrypted_key[:40], "...")
    print("hybrid round-trip works:", hybrid_decrypt(private_key, encrypted_data, encrypted_key) == long_text)
