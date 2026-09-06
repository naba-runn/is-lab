from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes_generate_key():
    return "1234567890123456"


def aes_encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes_decrypt(key, ciphertext):
    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

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
