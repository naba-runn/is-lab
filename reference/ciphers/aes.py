from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes_generate_key():
    return "1234567890123456"


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


if __name__ == "__main__":
    key = aes_generate_key()
    data = "Hello AES"

    encrypted = aes_encrypt(key, data)
    print("Plaintext :", data)
    print("Encrypted :", encrypted)

    decrypted = aes_decrypt(key, encrypted)
    print("Decrypted :", decrypted)

# aes_encrypt(key, plaintext, iv=...) also accepts a given IV (bytes, exactly
# AES.block_size long) instead of generating a random one, and `key` can be
# raw bytes instead of a string -- useful when a question hands you a
# specific IV, or when the key comes from a hash/KDF rather than typed text.
# The key length alone (16/24/32 bytes) selects AES-128/192/256 automatically.
