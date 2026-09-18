import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ---- from ciphers/des.py (verbatim) ----

def des_generate_key():
    return "12345678"


def des_encrypt(key, plaintext):
    cipher = DES.new(key.encode(), DES.MODE_ECB)

    return cipher.encrypt(pad(plaintext.encode(), DES.block_size)).hex()


def des_decrypt(key, ciphertext):
    cipher = DES.new(key.encode(), DES.MODE_ECB)

    return unpad(cipher.decrypt(bytes.fromhex(ciphertext)), DES.block_size).decode()


# ---- from ciphers/aes.py (verbatim) ----
# A 32-character key is 32 bytes once encoded -> AES automatically runs in
# AES-256 mode. No AES-256-specific code is needed; it's the exact same
# aes_encrypt/aes_decrypt used everywhere else in ciphers/.

def aes_generate_key():
    return "A" * 32


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


def measure(fn, *args, repeats=10000):
    start = time.perf_counter()
    for _ in range(repeats):
        result = fn(*args)
    elapsed = time.perf_counter() - start

    return result, elapsed / repeats


if __name__ == "__main__":
    message = "Performance Testing of Encryption Algorithms"

    des_key = des_generate_key()
    aes_key = aes_generate_key()   # 32 chars -> AES-256

    des_ciphertext, des_encrypt_time = measure(des_encrypt, des_key, message)
    _, des_decrypt_time = measure(des_decrypt, des_key, des_ciphertext)

    aes_ciphertext, aes_encrypt_time = measure(aes_encrypt, aes_key, message)
    _, aes_decrypt_time = measure(aes_decrypt, aes_key, aes_ciphertext)

    print("Message :", message)
    print()
    print(f"{'Algorithm':>10} {'Encrypt avg (us)':>18} {'Decrypt avg (us)':>18}")
    print(f"{'DES':>10} {des_encrypt_time * 1e6:>18.2f} {des_decrypt_time * 1e6:>18.2f}")
    print(f"{'AES-256':>10} {aes_encrypt_time * 1e6:>18.2f} {aes_decrypt_time * 1e6:>18.2f}")

    print()
    print("Findings:")
    print("- DES uses a 56-bit effective key and a 64-bit block; AES-256 uses a 256-bit key")
    print("  and a 128-bit block. AES does more rounds of a more elaborate round function,")
    print("  but its design is optimized for modern CPUs, so in practice it is typically as")
    print("  fast as, or faster than, DES despite the much larger security margin.")
    print("- DES's 56-bit key is brute-forceable with modern hardware and is considered")
    print("  broken for real use; AES-256 is the current recommended standard for")
    print("  high-security applications.")
    print("- Exact timings above depend on the machine and Python/OpenSSL build; run")
    print("  multiple times and compare relative, not absolute, numbers.")
