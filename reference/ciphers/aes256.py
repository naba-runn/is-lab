from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes256_demo_key():
    # FIXED demo key, not random -- use the key given in the question
    # 64 hex chars = 32 bytes -> AES-256
    return "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"


def aes256_encrypt(key_hex, plaintext):
    # bytes.fromhex() decodes the hex digits into 32 raw bytes.
    # key_hex.encode() would instead treat the 64-character string as literal
    # ASCII text -> 64 bytes -> not a valid AES key size at all (crashes).
    key = bytes.fromhex(key_hex)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes256_decrypt(key_hex, ciphertext):
    key = bytes.fromhex(key_hex)

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


if __name__ == "__main__":
    key = aes256_demo_key()
    message = "Encryption Strength"

    ciphertext = aes256_encrypt(key, message)
    decrypted = aes256_decrypt(key, ciphertext)

    print("Key (hex)  :", key, f"({len(bytes.fromhex(key)) * 8}-bit)")
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)
