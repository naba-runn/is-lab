from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes128_demo_key():
    # FIXED demo key, not random -- use the key given in the question
    # 32 hex chars = 16 bytes -> AES-128
    return "0123456789ABCDEF0123456789ABCDEF"


def aes128_encrypt(key_hex, plaintext):
    # bytes.fromhex() decodes the hex digits into 16 raw bytes.
    # key_hex.encode() would instead treat the 32-character string as literal
    # ASCII text -> 32 bytes -> silently becomes AES-256, not AES-128.
    key = bytes.fromhex(key_hex)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes128_decrypt(key_hex, ciphertext):
    key = bytes.fromhex(key_hex)

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


if __name__ == "__main__":
    key = aes128_demo_key()
    message = "Sensitive Information"

    ciphertext = aes128_encrypt(key, message)
    decrypted = aes128_decrypt(key, ciphertext)

    print("Key (hex)  :", key, f"({len(bytes.fromhex(key)) * 8}-bit)")
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)
