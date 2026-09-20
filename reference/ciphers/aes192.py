from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def aes192_generate_key():
    # 48 hex chars = 24 bytes -> AES-192
    return "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"


def aes192_encrypt(key_hex, plaintext):
    # bytes.fromhex() decodes the hex digits into 24 raw bytes.
    # key_hex.encode() would instead treat the 48-character string as literal
    # ASCII text -> 48 bytes -> not a valid AES key size at all (crashes).
    key = bytes.fromhex(key_hex)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes192_decrypt(key_hex, ciphertext):
    key = bytes.fromhex(key_hex)

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


if __name__ == "__main__":
    key = aes192_generate_key()
    message = "Top Secret Data"

    ciphertext = aes192_encrypt(key, message)
    decrypted = aes192_decrypt(key, ciphertext)

    print("Key (hex)  :", key, f"({len(bytes.fromhex(key)) * 8}-bit)")
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)
